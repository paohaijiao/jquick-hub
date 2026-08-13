package com.gateway.handler;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.util.ReferenceCountUtil;
import io.netty.util.concurrent.ScheduledFuture;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * 非HTTP/HTTPS流量 前置magic-token 握手鉴权 Handler（增量开发，不影响原有HTTP/HTTPS转发）。
 *
 * <p><b>背景</b>：数据库连接工具、ssh 客户端等原生TCP工具没有自定义请求头、无法修改应用层协议、
 * 不能要求其发送自定义token报文。因此采用【TCP连接建立后，第一个业务数据包最前面拼接固定长度token字节，
 * 紧跟真实业务报文】的方案，客户端侧由本地迷你代理/socat 自动拼接token，原生工具零修改。
 *
 * <p><b>工作流程</b>：
 * <ol>
 *   <li>由 {@link JQuickProtocolDetectHandler#finish} 判定为"普通TCP流量"后调用 {@link #begin} 进入鉴权态；
 *       HTTP/HTTPS 流量不会走到 begin（探测Handler直接转发给relay），本Handler对其一律透传。</li>
 *   <li>累积收到的字节，取前 token-prefix-len 字节与合法token列表比对（<b>只读不消费</b>，用 getBytes 窥视）；</li>
 *   <li>校验通过：消费(剥离)前置token字节，剩余真实业务数据原样交给原有转发Handler建连透传，后续字节流全透传；</li>
 *   <li>校验失败 / 超时未收全token：<b>静默关闭连接，不返回任何应答</b>（防信息泄露）。</li>
 * </ol>
 *
 * <p><b>边界处理</b>：
 * <ul>
 *   <li><b>粘包</b>：客户端首包可能同时包含 token+业务数据，也可能token被拆成多包，统一累积到 authBuffer 处理；</li>
 *   <li><b>拆包</b>：authBuffer 不足 tokenLen 时继续等待，由 timeoutTask 超时兜底关闭；</li>
 *   <li><b>token剥离</b>：通过 readerIndex 推进消费 token 前缀，剩余部分用 slice+retain 切片透传，业务数据零拷贝；</li>
 *   <li><b>日志安全</b>：token 只做掩码输出（前4+后2），绝不打印明文；</li>
 *   <li><b>时序比对</b>：使用 {@link MessageDigest#isEqual} 常量时间比较，避免时序侧信道。</li>
 * </ul>
 */
public class JQuickAuthPrefixHandler extends ChannelInboundHandlerAdapter {

    private static final Logger log = LoggerFactory.getLogger(JQuickAuthPrefixHandler.class);

    private final boolean enabled;

    private final int tokenLen;

    private final byte[][] validTokens;

    private final int authTimeoutMs;

    private boolean initiated;

    private boolean authPassed;

    private boolean authFailed;

    private String targetHost;

    private int targetPort;

    private ByteBuf authBuffer;

    private ScheduledFuture<?> timeoutTask;

    public JQuickAuthPrefixHandler(boolean enabled, int tokenLen, List<String> validTokens, int authTimeoutMs) {
        this.enabled = enabled;
        this.tokenLen = tokenLen;
        this.authTimeoutMs = authTimeoutMs > 0 ? authTimeoutMs : 5000;
        this.validTokens = new byte[validTokens == null ? 0 : validTokens.size()][];
        if (validTokens != null) {
            for (int i = 0; i < validTokens.size(); i++) {
                this.validTokens[i] = validTokens.get(i).getBytes(StandardCharsets.UTF_8);
            }
        }
    }

    public boolean isEnabled() {
        return enabled;
    }

    /**
     * 由 {@link JQuickProtocolDetectHandler#finish} 在判定为"普通TCP流量"后调用。
     * HTTP/HTTPS 流量不会进入本方法（探测Handler直接转发给relay）。
     *
     * @param firstData 探测期累积的原始字节（所有权移交；可能仅含部分token，也可能已含 token+业务数据）
     */
    public void begin(ChannelHandlerContext ctx, String host, int port, ByteBuf firstData) {
        this.initiated = true;
        this.targetHost = host;
        this.targetPort = port;

        if (!enabled) {
            relay(ctx).initiate(ctx, host, port, firstData);
            authPassed = true;
            return;
        }

        scheduleAuthTimeout(ctx);
        if (firstData != null) {
            process(ctx, firstData);
        }
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (!initiated || !enabled || authPassed) {
            ctx.fireChannelRead(msg);
            return;
        }
        process(ctx, (ByteBuf) msg);
    }

    /**
     * 鉴权核心逻辑：
     * 累积字节 → 窥视比对token → 通过则剥离token并转交转发层；失败则静默关闭。
     */
    private void process(ChannelHandlerContext ctx, ByteBuf in) {
        if (authFailed) {
            in.release();
            return;
        }
        append(ctx, in);
        if (authBuffer.readableBytes() < tokenLen) {
            return;
        }

        byte[] head = new byte[tokenLen];
        authBuffer.getBytes(authBuffer.readerIndex(), head);
        if (!matches(head)) {
            log.warn("鉴权失败: token={}，静默关闭连接", mask(head));
            authFailed = true;
            cancelTimeout();
            releaseBuffer();
            ctx.close(); // 不返回任何应答，防信息泄露
            return;
        }

        authPassed = true;
        cancelTimeout();
        int remainingLen = authBuffer.readableBytes() - tokenLen;
        ByteBuf remaining = remainingLen > 0
                ? authBuffer.slice(tokenLen, remainingLen).retain()
                : null;
        releaseBuffer();
        log.info("鉴权通过(掩码 {}), 剥离{}字节token, 透传{}字节业务数据", mask(head), tokenLen, remainingLen);
        relay(ctx).initiate(ctx, targetHost, targetPort, remaining);
    }

    /** 追加累积（token前缀可能跨多个TCP包到达，粘包/拆包统一处理） */
    private void append(ChannelHandlerContext ctx, ByteBuf in) {
        if (authBuffer == null) {
            authBuffer = in; // 接管，所有权移交
            return;
        }
        ByteBuf merged = ctx.alloc().buffer(authBuffer.readableBytes() + in.readableBytes());
        merged.writeBytes(authBuffer);
        merged.writeBytes(in);
        authBuffer.release();
        in.release();
        authBuffer = merged;
    }

    /** 常量时间比对token，避免时序侧信道 */
    private boolean matches(byte[] head) {
        for (byte[] t : validTokens) {
            if (t.length == head.length && MessageDigest.isEqual(head, t)) {
                return true;
            }
        }
        return false;
    }

    /** 鉴权超时：连接建立后未在限定时间内收到完整token → 静默关闭 */
    private void scheduleAuthTimeout(final ChannelHandlerContext ctx) {
        timeoutTask = ctx.executor().schedule(() -> {
            if (authPassed || authFailed) {
                return;
            }
            log.warn("鉴权超时({}ms)未收到完整token，静默关闭连接", authTimeoutMs);
            releaseBuffer();
            ctx.close();
        }, authTimeoutMs, TimeUnit.MILLISECONDS);
    }

    private void cancelTimeout() {
        if (timeoutTask != null) {
            timeoutTask.cancel(false);
            timeoutTask = null;
        }
    }

    private JQuickTcpRelayHandler relay(ChannelHandlerContext ctx) {
        return ctx.pipeline().get(JQuickTcpRelayHandler.class);
    }

    /** token掩码：仅显示前4位+后2位，禁止打印明文 */
    private static String mask(byte[] b) {
        if (b == null || b.length == 0) {
            return "****";
        }
        String s = new String(b, StandardCharsets.UTF_8);
        if (s.length() <= 4) {
            return "****";
        }
        return s.substring(0, 4) + "****" + s.substring(s.length() - 2);
    }

    private void releaseBuffer() {
        if (authBuffer != null) {
            ReferenceCountUtil.release(authBuffer);
            authBuffer = null;
        }
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        cancelTimeout();
        releaseBuffer();
        super.channelInactive(ctx);
    }

    @Override
    public void handlerRemoved(ChannelHandlerContext ctx) throws Exception {
        cancelTimeout();
        releaseBuffer();
        super.handlerRemoved(ctx);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        cancelTimeout();
        releaseBuffer();
        log.warn("鉴权阶段异常，关闭连接: {}", cause.toString());
        ctx.close();
    }
}
