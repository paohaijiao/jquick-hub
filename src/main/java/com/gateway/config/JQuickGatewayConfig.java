package com.gateway.config;

import lombok.Data;

/**
 * 网关配置模型（全部业务参数，由 ConfigLoader 从 YAML 填充）。
 */
@Data
public class JQuickGatewayConfig {
    /**
     * 公网监听端口
     */
    private int listenPort;
    /**
     * 监听网卡 IP（默认 0.0.0.0 = 监听所有网卡；可用环境变量 JQUICK_LISTEN_HOST 覆盖）
     */
    private String listenHost;
    /**
     * TCP backlog
     */
    private int listenBacklog;
    /**
     *  连接超时毫秒(后端建连超时 / 探测等待上限)
     */
    private int listenSoTimeout;

    /**
     *  连接超时毫秒(后端建连超时 / 探测等待上限)
     */
    private int probeTimeoutMs;

    /**
     * 分流目标: 内网 Nginx ----
     */
    private String nginxHost;
    /**
     * Nginx 端口
     */
    private int nginxPort;

    /**
     * 非 HTTP/HTTPS 流量转发目标
     */
    private String otherHost;    // 指定转发 IP
    /**
     * 指定转发端口
     */
    private int otherPort;

    // Netty 调优参数boss 线程数 ----
    private int bossThreads;
    /**
     * worker 线程数 (0 = 自动)
     */
    private int workerThreads;
    /**
     * 缓冲区泄漏检测级别
     */
    private String leakDetection;

    // ==================== 增量: 非HTTP/HTTPS流量前置token鉴权 ====================

    /**
     * 普通TCP流量鉴权开关（other.traffic.auth.enable，生产默认开启）
     */
    private boolean otherAuthEnabled;
    /**
     * 前置magic-token固定长度（字节）（other.traffic.auth.token-prefix-len）
     */
    private int otherAuthTokenPrefixLen;
    /**
     * 鉴权超时毫秒：连接建立后未在限定时间内收到完整token则静默关闭（other.traffic.auth.timeout_ms）
     */
    private int otherAuthTimeoutMs;
    /**
     * 合法token列表（other.traffic.auth.valid-tokens），每项长度必须等于 token-prefix-len
     */
    private java.util.List<String> otherAuthValidTokens;


}
