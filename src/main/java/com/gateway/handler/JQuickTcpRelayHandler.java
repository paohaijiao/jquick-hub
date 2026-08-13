package com.gateway.handler;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.socket.SocketChannel;
import io.netty.util.ReferenceCountUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 通用双向透传转发 Handler。
 *
 * <p>一个类两种角色（由 {@code isBackend} 区分）：
 * <ul>
 *   <li><b>前端侧</b>（isBackend=false）：挂在外网客户端连接上。
 *       由 {@link JQuickProtocolDetectHandler} 完成协议判定后调用 {@link #initiate} 发起后端建连；
 *       后端未就绪前的数据暂存在 {@code buffered} 缓冲，就绪后一次性刷出，保证零丢包。</li>
 *   <li><b>后端侧</b>（isBackend=true）：挂在转发目标连接上，把后端数据原样写回前端。</li>
 * </ul>
 *
 * <p>健壮性要点：
 * <ul>
 *   <li>双向透传、长连接支持：不解析任何数据，仅搬运字节</li>
 *   <li>断连联动：前端断开 → 关闭后端；后端断开 → 关闭前端；写失败/异常 → 双端关闭</li>
 *   <li>后端连接失败 → 立即关闭前端连接（requirement 4.1）</li>
 *   <li>背压控制：对端写缓冲满时暂停本端读取（setAutoRead），防止内存无限堆积</li>
 *   <li>引用计数安全：所有暂存缓冲在关闭/移除时释放，避免内存泄漏</li>
 * </ul>
 */
public class JQuickTcpRelayHandler extends ChannelInboundHandlerAdapter {

    private static final Logger log = LoggerFactory.getLogger(JQuickTcpRelayHandler.class);

    /** 后端连接 Bootstrap（由启动主类配置好事件循环与超时，可 clone 复用） */
    private final Bootstrap backendBootstrap;
    /** 是否为后端（转发目标）侧 Handler */
    private final boolean isBackend;
    /** 后端侧持有的前端通道引用（用于把后端数据写回前端） */
    private final Channel frontendChannel;

    private Channel backendChannel;   // 已建立的后端连接

    private ByteBuf buffered;         // 后端未就绪期间暂存的前端数据

    private boolean backendReady;     // 后端连接是否已就绪

    private String targetHost;        // 转发目标 host

    private int targetPort;           // 转发目标 port

    private JQuickTcpRelayHandler(boolean isBackend, Channel frontendChannel, Bootstrap backendBootstrap) {
        this.isBackend = isBackend;
        this.frontendChannel = frontendChannel;
        this.backendBootstrap = backendBootstrap;
    }

    /** 创建前端侧 Handler（挂在公网客户端连接上） */
    public static JQuickTcpRelayHandler frontend(Bootstrap backendBootstrap) {
        return new JQuickTcpRelayHandler(false, null, backendBootstrap);
    }

    /** 创建后端侧 Handler（挂在转发目标连接上） */
    public static JQuickTcpRelayHandler backend(Channel frontendChannel) {
        return new JQuickTcpRelayHandler(true, frontendChannel, null);
    }

    /**
     * 前端侧：协议探测完成后调用，发起后端连接并把探测期累积的数据交给本 Handler。
     *
     * @param frontendCtx 前端通道上下文
     * @param host        转发目标 IP
     * @param port        转发目标端口
     * @param firstData   探测期累积的原始字节（所有权移交，可为 null）
     */
    public void initiate(ChannelHandlerContext frontendCtx, String host, int port, ByteBuf firstData) {
        this.targetHost = host;
        this.targetPort = port;
        if (firstData != null) {
            this.buffered = firstData; // 直接接管，不拷贝
        }

        backendBootstrap.clone()
                .handler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) {
                        // 后端通道的 Handler 持有前端通道引用，用于回流数据
                        ch.pipeline().addLast(JQuickTcpRelayHandler.backend(frontendCtx.channel()));
                    }
                })
                .connect(host, port)
                .addListener((ChannelFutureListener) f -> {
                    Channel front = frontendCtx.channel();
                    if (!f.isSuccess()) {
                        // 后端目标地址连接失败 → 关闭客户端连接（requirement 4.1）
                        log.warn("后端连接失败 {}:{} - {}", host, port, f.cause());
                        releaseBuffered();
                        front.close();
                        return;
                    }
                    final Channel backend = f.channel();
                    // 状态变更回到前端事件循环执行，与 channelRead 串行化，避免并发问题
                    front.eventLoop().execute(() -> {
                        if (!front.isActive()) {
                            // 前端已断开，立即关闭刚建立的后端连接
                            backend.close();
                            return;
                        }
                        backendChannel = backend;
                        backendReady = true;
                        log.debug("后端连接成功 {}:{}，开始透传", host, port);
                        flushBufferedToBackend(frontendCtx);
                    });
                });
    }


    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (isBackend) {
            //后端 → 前端：透传后端数据给客户端
            writeToFrontend(ctx, (ByteBuf) msg);
            return;
        }
        //前端 → 后端
        if (!backendReady) {
            // 后端尚未就绪，暂存数据（TCP 探测期数据在此缓冲，不丢包）
            appendBuffered(ctx, (ByteBuf) msg);
            return;
        }
        writeToBackend(ctx, (ByteBuf) msg);
    }

    /** 前端数据写向后端 */
    private void writeToBackend(ChannelHandlerContext ctx, ByteBuf data) {
        if (backendChannel == null || !backendChannel.isActive()) {
            data.release();
            ctx.close();
            return;
        }
        // 背压：后端写缓冲已满，暂停从前端读
        if (!backendChannel.isWritable()) {
            ctx.channel().config().setAutoRead(false);
        }
        backendChannel.writeAndFlush(data).addListener((ChannelFutureListener) f -> {
            if (!f.isSuccess()) {
                log.warn("写入后端失败，关闭双端连接: {}", f.cause());
                closeBoth(ctx, backendChannel);
            }
        });
    }

    /** 后端数据写回前端 */
    private void writeToFrontend(ChannelHandlerContext ctx, ByteBuf data) {
        if (frontendChannel == null || !frontendChannel.isActive()) {
            data.release();
            ctx.close();
            return;
        }
        // 背压：前端写缓冲已满，暂停从后端读
        if (!frontendChannel.isWritable()) {
            ctx.channel().config().setAutoRead(false);
        }
        frontendChannel.writeAndFlush(data).addListener((ChannelFutureListener) f -> {
            if (!f.isSuccess()) {
                log.warn("写入前端失败，关闭双端连接: {}", f.cause());
                closeBoth(ctx, frontendChannel);
            }
        });
    }


    /**
     * 通道可写状态变化时恢复读取。
     * 前端通道变可写 → 恢复从后端读；后端通道变可写 → 恢复从前端读。
     */
    @Override
    public void channelWritabilityChanged(ChannelHandlerContext ctx) {
        if (isBackend) {
            // 后端缓冲恢复可写 → 前端重新可读
            if (frontendChannel != null && ctx.channel().isWritable()) {
                frontendChannel.config().setAutoRead(true);
            }
        } else {
            // 前端缓冲恢复可写 → 后端重新可读
            if (backendChannel != null && ctx.channel().isWritable()) {
                backendChannel.config().setAutoRead(true);
            }
        }
        ctx.fireChannelWritabilityChanged();
    }


    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        if (isBackend) {
            if (frontendChannel != null && frontendChannel.isActive()) {
                frontendChannel.close();
            }
        } else {
            if (backendChannel != null && backendChannel.isActive()) {
                backendChannel.close();
            }
            releaseBuffered();
        }
        ctx.fireChannelInactive();
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        log.warn("转发阶段异常，关闭连接: {}", cause.toString());
        if (isBackend) {
            if (frontendChannel != null) {
                frontendChannel.close();
            }
            ctx.close();
        } else {
            if (backendChannel != null) {
                backendChannel.close();
            }
            ctx.close();
        }
    }

    @Override
    public void handlerRemoved(ChannelHandlerContext ctx) throws Exception {
        if (!isBackend) {
            releaseBuffered(); // 防止缓冲内存泄漏
        }
        super.handlerRemoved(ctx);
    }
    /** 后端就绪后把暂存数据一次性刷出 */
    private void flushBufferedToBackend(ChannelHandlerContext frontendCtx) {
        if (buffered == null) {
            return;
        }
        ByteBuf data = buffered;
        buffered = null;
        if (backendChannel != null && backendChannel.isActive()) {
            backendChannel.writeAndFlush(data).addListener((ChannelFutureListener) f -> {
                if (!f.isSuccess()) {
                    log.warn("刷新暂存数据到后端失败，关闭双端连接: {}", f.cause());
                    closeBoth(frontendCtx, backendChannel);
                }
            });
        } else {
            data.release();
            frontendCtx.close();
        }
    }

    /** 暂存缓冲合并（后端未就绪期间收到的数据） */
    private void appendBuffered(ChannelHandlerContext ctx, ByteBuf in) {
        if (buffered == null) {
            buffered = in;
            return;
        }
        ByteBuf merged = ctx.alloc().buffer(buffered.readableBytes() + in.readableBytes());
        merged.writeBytes(buffered);
        merged.writeBytes(in);
        buffered.release();
        in.release();
        buffered = merged;
    }

    private void releaseBuffered() {
        if (buffered != null) {
            ReferenceCountUtil.release(buffered);
            buffered = null;
        }
    }

    private void closeBoth(ChannelHandlerContext ctx, Channel other) {
        if (other != null && other.isActive()) {
            other.close();
        }
        ctx.close();
    }
}
