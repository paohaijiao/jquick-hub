package com.gateway;

import com.gateway.config.JQuickConfigLoader;
import com.gateway.config.JQuickGatewayConfig;
import com.gateway.handler.JQuickAuthPrefixHandler;
import com.gateway.handler.JQuickProtocolDetectHandler;
import com.gateway.handler.JQuickTcpRelayHandler;
import com.github.paohaijiao.console.JConsole;
import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.util.ResourceLeakDetector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * TCP 流量网关启动主类。
 *
 * <p>监听公网单个 TCP 端口，首包协议嗅探分流：
 * <ul>
 *   <li>HTTP / HTTPS(TLS) → 透传转发到内网 Nginx（Netty 不解析、不解密、不改写）</li>
 *   <li>其他普通 TCP 流量 → 透传转发到配置文件指定的目标 IP+端口</li>
 * </ul>
 *
 * <p>启动方式：
 * <pre>
 *   java -jar tcp-gateway.jar [配置文件路径]
 * </pre>
 * 配置文件不传时依次查找：环境变量 GATEWAY_CONFIG → 工作目录 gateway.yaml → classpath 内置默认。
 */
public final class JQuickGatewayServer {

    public static JConsole log=JConsole.initConsoleEnvironment();

    private JQuickGatewayServer() {
    }

    public static void main(String[] args) {
        JQuickGatewayConfig config = JQuickConfigLoader.load(args.length > 0 ? args[0] : null);
        setLeakDetection(config.getLeakDetection());
        JQuickGatewayServer gateway = new JQuickGatewayServer();
        gateway.start(config);
    }

    /**
     * 启动监听。
     * 进程将一直运行，直到收到 SIGTERM/SIGINT（通过 shutdown hook 优雅关闭）。
     */
    private void start(JQuickGatewayConfig config) {
        // boss 线程组：负责接受新的 TCP 连接
        EventLoopGroup bossGroup = new NioEventLoopGroup(config.getBossThreads());
        // worker 线程组：负责读写 IO；配置为 0 时自动按 CPU 核数 * 2
        int workerThreads = config.getWorkerThreads() > 0 ? config.getWorkerThreads() : Math.max(1, Runtime.getRuntime().availableProcessors() * 2);
        EventLoopGroup workerGroup = new NioEventLoopGroup(workerThreads);
        // 注册 JVM 关闭钩子，优雅关闭事件循环，避免连接被粗暴掐断
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            log.info("收到关闭信号，正在优雅关闭...");
            bossGroup.shutdownGracefully();
            workerGroup.shutdownGracefully();
        }));
        // 后端连接 Bootstrap（供前端 Handler 建连到 Nginx / 其他目标时 clone 复用）
        Bootstrap backendBootstrap = new Bootstrap()
                .group(workerGroup)
                .channel(NioSocketChannel.class)
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, config.getListenSoTimeout())
                .option(ChannelOption.SO_KEEPALIVE, true)
                .option(ChannelOption.TCP_NODELAY, true);

        try {
            ServerBootstrap server = new ServerBootstrap()
                    .group(bossGroup, workerGroup)
                    .channel(NioServerSocketChannel.class)
                    // TCP backlog：内核未决连接队列长度
                    .option(ChannelOption.SO_BACKLOG, config.getListenBacklog())
                    .option(ChannelOption.SO_REUSEADDR, true)
                    .childOption(ChannelOption.SO_KEEPALIVE, true)
                    .childOption(ChannelOption.TCP_NODELAY, true)
                    .childHandler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        protected void initChannel(SocketChannel ch) {
                            // 链路: 协议探测 -> (普通TCP流量鉴权) -> 双向透传
                            // 探测 Handler 只"偷看"首包字节，判定后把原始数据交给转发 Handler 建连转发；
                            // HTTP/HTTPS 由探测 Handler 直接交给转发 Handler（不执行鉴权）；
                            // 普通TCP流量且开启鉴权时，先由鉴权 Handler 校验/剥离前置token，再交给转发 Handler。
                            ch.pipeline().addLast(new JQuickProtocolDetectHandler(
                                    config.getProbeTimeoutMs(),
                                    new JQuickProtocolDetectHandler.Target(config.getNginxHost(), config.getNginxPort()),
                                    new JQuickProtocolDetectHandler.Target(config.getOtherHost(), config.getOtherPort())));
                            // ==== 增量: 非HTTP/HTTPS流量 前置magic-token鉴权 Handler ====
                            // 必须插在"探测Handler之后、转发Handler之前"：
                            //  - 探测Handler判定为 OTHER 时通过 auth.begin() 进入鉴权态；
                            //  - HTTP/HTTPS 不会触发鉴权，本 Handler 一律透传；
                            //  - 未开启鉴权(enabled=false)时完全透传，行为与旧版一致。
                            ch.pipeline().addLast(new JQuickAuthPrefixHandler(
                                    config.isOtherAuthEnabled(),
                                    config.getOtherAuthTokenPrefixLen(),
                                    config.getOtherAuthValidTokens(),
                                    config.getOtherAuthTimeoutMs()));
                            ch.pipeline().addLast(JQuickTcpRelayHandler.frontend(backendBootstrap));
                        }
                    });

            ChannelFuture future = server.bind(config.getListenPort()).sync();
            log.info("===============================================================");
            log.info("  TCP 流量网关启动成功");
            log.info("  公网监听: 0.0.0.0:{} (backlog={}, so_timeout={}ms)",
                    config.getListenPort(), config.getListenBacklog(), config.getListenSoTimeout());
            log.info("  HTTP/HTTPS -> Nginx : {}:{}", config.getNginxHost(), config.getNginxPort());
            log.info("  OTHER      -> 目标 : {}:{}", config.getOtherHost(), config.getOtherPort());
            log.info("  OTHER鉴权   : {} (前置token{}字节, 超时{}ms, 合法token数{})",
                    config.isOtherAuthEnabled() ? "开启(前置magic-token)" : "关闭",
                    config.getOtherAuthTokenPrefixLen(),
                    config.getOtherAuthTimeoutMs(),
                    config.getOtherAuthValidTokens() == null ? 0 : config.getOtherAuthValidTokens().size());
            log.info("  boss={} worker={} leakDetection={}",
                    config.getBossThreads(), workerThreads, config.getLeakDetection());
            log.info("===============================================================");

            // 阻塞等待，直到连接关闭（正常情况不会关闭）
            future.channel().closeFuture().sync();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("网关启动被中断", e);
        } finally {
            log.info("网关退出");
            bossGroup.shutdownGracefully();
            workerGroup.shutdownGracefully();
        }
    }

    /** 设置缓冲区泄漏检测级别：SIMPLE | ADVANCED | PARANOID | DISABLED */
    private static void setLeakDetection(String level) {
        try {
            ResourceLeakDetector.Level lv = ResourceLeakDetector.Level.valueOf(level.trim().toUpperCase());
            ResourceLeakDetector.setLevel(lv);
            log.info("缓冲区泄漏检测级别: {}", lv);
        } catch (IllegalArgumentException e) {
            log.warn("非法的泄漏检测级别配置: {}，使用默认 SIMPLE", level);
            ResourceLeakDetector.setLevel(ResourceLeakDetector.Level.SIMPLE);
        }
    }
}
