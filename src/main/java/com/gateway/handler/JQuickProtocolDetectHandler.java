package com.gateway.handler;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.util.ReferenceCountUtil;
import io.netty.util.concurrent.ScheduledFuture;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.TimeUnit;

public class JQuickProtocolDetectHandler extends ChannelInboundHandlerAdapter {

    private static final Logger log = LoggerFactory.getLogger(JQuickProtocolDetectHandler.class);

    private final Target nginxTarget;

    private final Target otherTarget;

    private final int probeTimeoutMs;
    /**
     * 累积缓冲：保存探测期间收到的全部原始字节
     */
    private ByteBuf pending;
    /**
     * 是否已完成协议判定
     */
    private boolean decided;
    /**
     * 探测超时任务
     */
    private ScheduledFuture<?> timeoutTask;

    /**
     * TLS 握手记录的首字节固定为 0x16（TLS Handshake），见 RFC 5246 第 6.2.1 节
     */
    private static final int TLS_HANDSHAKE_FIRST_BYTE = 0x16;

    /**
     * 已知 HTTP 方法（RFC 7231/5789），用于前缀匹配
     */
    private static final String[] HTTP_METHODS = {
            "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"
    };

    /**
     *  探测参考字节数：取最长方法名 OPTIONS(7) + 空格(1) = 8，留余量取 16；
     *  首包超过该长度仍未命中任何特征，即判定为"其他流量"
     */
    private static final int PROBE_MAX_BYTES = 16;

    /**
     * 探测阶段累积缓冲上限（字节），防止客户端在判定前疯狂灌数据导致内存膨胀
     */
    private static final int MAX_PROBE_BUFFER = 64 * 1024;

    public enum ProtocolType {
        /** 已识别为 HTTP */
        HTTP,
        /** 已识别为 HTTPS/TLS */
        TLS,
        /** 已识别为其他普通 TCP 流量 */
        OTHER,
        /** 数据不足，尚未判定，需要继续等待 */
        UNKNOWN
    }

    public static final class Target {
        public final String host;
        public final int port;

        public Target(String host, int port) {
            this.host = host;
            this.port = port;
        }

        @Override
        public String toString() {
            return host + ":" + port;
        }
    }




    public JQuickProtocolDetectHandler(int probeTimeoutMs, Target nginxTarget, Target otherTarget) {
        this.probeTimeoutMs = probeTimeoutMs > 0 ? probeTimeoutMs : 5000;
        this.nginxTarget = nginxTarget;
        this.otherTarget = otherTarget;
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        // 协议已判定：直接放行给下游转发 Handler，本 Handler 不再干预（不改写、不解析、透传原始字节）
        if (decided) {
            ctx.fireChannelRead(msg);
            return;
        }
        ByteBuf in = (ByteBuf) msg;
        if (pending == null && timeoutTask == null) {
            scheduleProbeTimeout(ctx);
        }
        append(ctx, in);
        if (decided) {
            return;
        }
        ProtocolType type = detect(pending);
        if (type == ProtocolType.UNKNOWN) {
            return;
        }
        finish(ctx, type);
    }

    /**
     * 将本次读到的 ByteBuf 追加进 pending 累积缓冲。
     * 追加逻辑：
     * <ul>
     *   <li>pending 为空 → 直接接管该缓冲（零拷贝）</li>
     *   <li>pending 非空 → 合并到一个新缓冲（TCP 拆包场景的累积）</li>
     * </ul>
     */
    private void append(ChannelHandlerContext ctx, ByteBuf in) {
        if (pending == null) {
            pending = in; // 接管，所有权移交，不再由 msg 释放
            return;
        }
        // 累积合并：新缓冲 = pending + in，随后释放旧的 pending 和 in
        int total = pending.readableBytes() + in.readableBytes();
        ByteBuf merged = ctx.alloc().buffer(total);
        merged.writeBytes(pending);
        merged.writeBytes(in);
        pending.release();
        in.release();
        pending = merged;
        // 防呆：累积超过上限仍未判定，直接按"其他流量"处理，避免内存无限增长
        if (pending.readableBytes() > MAX_PROBE_BUFFER) {
            log.warn("探测缓冲超过上限({}B)，按普通TCP流量处理", MAX_PROBE_BUFFER);
            finish(ctx, ProtocolType.OTHER);
        }
    }

    /**
     * 协议判定核心逻辑。
     * <b>只窥视不消费</b>：全部使用 getXXX 接口读取，不改动 readerIndex。
     *
     * @return 判定结果，UNKNOWN 表示数据不足需继续等待
     */
    private ProtocolType detect(ByteBuf buf) {
        int len = buf.readableBytes();

        // ---- 规则2：HTTPS(TLS) —— 首字节 0x16 = TLS Handshake，1 个字节即可判定 ----
        if (len >= 1 && (buf.getUnsignedByte(buf.readerIndex()) & 0xFF) == TLS_HANDSHAKE_FIRST_BYTE) {
            return ProtocolType.TLS;
        }

        // ---- 规则1：HTTP —— 前缀匹配已知方法，且方法名后紧跟空格(0x20) ----
        // 采用"方法前缀 + 长度"双重判断，正确处理 TCP 拆包：
        //   例如首包只有 "GET" 三个字节时（无空格），无法确定是完整方法，返回 UNKNOWN 等待；
        //   只有 "GET "（带空格）才确认为 HTTP。
        int maxMethodLen = maxMethodLength();
        int headLen = Math.min(len, maxMethodLen + 1); // 多看 1 字节，用于校验方法后的空格
        for (String method : HTTP_METHODS) {
            int m = method.length();
            if (len >= m + 1) {
                // 已有足够字节：精确比较方法名 + 空格
                if (prefixEquals(buf, method, m) && (buf.getByte(buf.readerIndex() + m) == ' ')) {
                    return ProtocolType.HTTP;
                }
            } else if (len > 0 && prefixEquals(buf, method, Math.min(m, headLen))) {
                // 数据不够方法全长：当前字节恰是某方法的前缀（可能拆包），不能否定 HTTP 可能，继续等待
                return ProtocolType.UNKNOWN;
            }
        }

        // ---- 规则3：其他流量 ----
        // 已收集到 PROBE_MAX_BYTES 字节仍不匹配任何特征 → 判定为普通 TCP 流量；
        // 字节数不足时返回 UNKNOWN 继续等待，避免把拆包的数据误判为普通流量。
        if (len >= PROBE_MAX_BYTES) {
            return ProtocolType.OTHER;
        }
        return ProtocolType.UNKNOWN;
    }

    /** 判定完成：取消超时任务，选择分流目标，把全部原始字节交给转发 Handler */
    private void finish(ChannelHandlerContext ctx, ProtocolType type) {
        if (decided) {
            return;
        }
        decided = true;
        cancelTimeout();
        Target target;
        switch (type) {
            case HTTP:
            case TLS:
                target = nginxTarget; // HTTP / HTTPS 统一转发到内网 Nginx
                log.debug("协议识别: {}，转发到 Nginx {}", type, target);
                break;
            case OTHER:
            default:
                target = otherTarget;
                log.debug("协议识别: OTHER，转发到 {}", target);
                break;
        }

        // 将 pending（探测期间累积的全部原始字节，一份不丢）交给转发 Handler 建连并转发
        JQuickTcpRelayHandler relay = ctx.pipeline().get(JQuickTcpRelayHandler.class);
        ByteBuf firstData = pending;
        pending = null; // 所有权移交，本 Handler 不再持有

        // ==== 增量: 普通TCP流量且启用前置token鉴权 → 先交给鉴权Handler剥离token再转发 ====
        // 仅 OTHER 类型走鉴权; HTTP/HTTPS 完全沿用原有逻辑, 不执行鉴权
        JQuickAuthPrefixHandler auth = ctx.pipeline().get(JQuickAuthPrefixHandler.class);
        if (type == ProtocolType.OTHER && auth != null && auth.isEnabled()) {
            auth.begin(ctx, target.host, target.port, firstData);
            return;
        }
        // ==== 原有逻辑保持不变 ====
        relay.initiate(ctx, target.host, target.port, firstData);
    }

    /** 启动探测超时任务：超时后已收到数据按 OTHER 转发，零数据则关闭连接 */
    private void scheduleProbeTimeout(final ChannelHandlerContext ctx) {
        timeoutTask = ctx.executor().schedule(() -> {
            if (decided) {
                return;
            }
            if (pending != null && pending.readableBytes() > 0) {
                log.warn("协议探测超时({}ms)，按普通TCP流量转发", probeTimeoutMs);
                finish(ctx, ProtocolType.OTHER);
            } else {
                log.warn("协议探测超时({}ms)且无任何数据，关闭连接", probeTimeoutMs);
                ctx.close();
            }
        }, probeTimeoutMs, TimeUnit.MILLISECONDS);
    }

    private void cancelTimeout() {
        if (timeoutTask != null) {
            timeoutTask.cancel(false);
            timeoutTask = null;
        }
    }

    /** 前缀匹配（大小写不敏感，部分客户端可能发送小写方法名） */
    private static boolean prefixEquals(ByteBuf buf, String s, int n) {
        int idx = buf.readerIndex();
        for (int i = 0; i < n; i++) {
            char c = (char) (buf.getByte(idx + i) & 0xFF);
            if (Character.toLowerCase(c) != Character.toLowerCase(s.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    private static int maxMethodLength() {
        int max = 0;
        for (String m : HTTP_METHODS) {
            if (m.length() > max) {
                max = m.length();
            }
        }
        return max;
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        cancelTimeout();
        releasePending();
        super.channelInactive(ctx);
    }

    @Override
    public void handlerRemoved(ChannelHandlerContext ctx) throws Exception {
        cancelTimeout();
        releasePending();
        super.handlerRemoved(ctx);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        cancelTimeout();
        releasePending();
        log.warn("协议探测阶段异常，关闭连接: {}", cause.toString());
        ctx.close();
    }

    private void releasePending() {
        if (pending != null) {
            ReferenceCountUtil.release(pending);
            pending = null;
        }
    }
}
