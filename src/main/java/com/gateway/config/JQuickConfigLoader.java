package com.gateway.config;

import com.github.paohaijiao.console.JConsole;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.Yaml;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public final class JQuickConfigLoader {

    public static JConsole log=JConsole.initConsoleEnvironment();

    /**
     * 默认配置文件路径（工作目录）
     */
    private static final String DEFAULT_PATH = "gateway.yaml";
    /**
     * classpath 内置默认配置
     */
    private static final String CLASSPATH_DEFAULT = "/gateway.yaml";

    private static final int DEFAULT_LISTEN_PORT = 8080;

    /** 默认监听网卡（0.0.0.0 = 监听所有网卡） */
    private static final String DEFAULT_LISTEN_HOST = "0.0.0.0";

    private static final int DEFAULT_BACKLOG = 1024;

    private static final int DEFAULT_SO_TIMEOUT = 5000;

    private static final int DEFAULT_PROBE_TIMEOUT = 5000;

    private static final String DEFAULT_NGINX_HOST = "127.0.0.1";

    private static final int DEFAULT_NGINX_PORT = 80;

    private static final String DEFAULT_OTHER_HOST = "127.0.0.1";

    private static final int DEFAULT_OTHER_PORT = 9000;

    private static final int DEFAULT_BOSS_THREADS = 1;

    private static final int DEFAULT_WORKER_THREADS = 0; // 0 = 自动

    private static final String DEFAULT_LEAK_DETECTION = "SIMPLE";

    // ---- 增量: 非HTTP/HTTPS流量前置token鉴权默认值 ----
    /** 生产默认开启鉴权(仅当配置文件中存在 auth 段时生效; 旧配置无 auth 段则默认关闭以保持兼容) */
    private static final boolean DEFAULT_OTHER_AUTH_ENABLE = true;
    /** 前置token默认固定长度(字节) */
    private static final int DEFAULT_OTHER_AUTH_TOKEN_PREFIX_LEN = 32;
    /** 鉴权超时默认毫秒 */
    private static final int DEFAULT_OTHER_AUTH_TIMEOUT_MS = 5000;

    private JQuickConfigLoader() {
    }

    /**
     * 加载配置。
     *
     * @param argPath 命令行传入的配置文件路径，可为 null
     * @return 完整配置对象
     */
    public static JQuickGatewayConfig load(String argPath) {
        String path = resolvePath(argPath);
        log.info("加载配置文件: {}", path);
        Map<String, Object> root;
        if (path != null) {
            try (InputStream in = new FileInputStream(path)) {
                root = parseYaml(in);
            } catch (IOException e) {
                log.warn("读取外部配置文件失败: {}，回退到 classpath 默认配置", path, e);
                root = loadFromClasspath();
            }
        } else {
            root = loadFromClasspath();
        }
        JQuickGatewayConfig cfg = buildConfig(root);
        // 环境变量覆盖(优先级: 环境变量 > YAML > 代码默认值), 支撑 Docker 容器化按需传参
        applyEnvOverrides(cfg);
        validate(cfg);
        log.info("配置加载完成: {}", cfg);
        return cfg;
    }

    /**
     * 解析配置文件路径：arg > 环境变量 > 工作目录默认文件 > classpath
     */
    private static String resolvePath(String argPath) {
        if (argPath != null && !argPath.trim().isEmpty()) {
            return argPath.trim();
        }
        String env = System.getenv("GATEWAY_CONFIG");
        if (env != null && !env.trim().isEmpty()) {
            return env.trim();
        }
        java.io.File f = new java.io.File(DEFAULT_PATH);
        if (f.isFile() && f.canRead()) {
            return f.getAbsolutePath();
        }
        return null;
    }

    /**
     * 从 classpath 加载内置默认配置
     */
    private static Map<String, Object> loadFromClasspath() {
        try (InputStream in = JQuickConfigLoader.class.getResourceAsStream(CLASSPATH_DEFAULT)) {
            if (in == null) {
                throw new IllegalStateException("classpath 中找不到默认配置文件: " + CLASSPATH_DEFAULT);
            }
            return parseYaml(in);
        } catch (IOException e) {
            throw new IllegalStateException("加载 classpath 默认配置失败", e);
        }
    }

    /**
     * 用 SnakeYAML 将输入流解析为嵌套 Map
     */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> parseYaml(InputStream in) {
        Yaml yaml = new Yaml();
        Object obj = yaml.load(in);
        if (obj == null) {
            return new java.util.HashMap<>();
        }
        return (Map<String, Object>) obj;
    }

    /**
     * 从 Map 逐级提取配置项并构造 GatewayConfig
     */
    private static JQuickGatewayConfig buildConfig(Map<String, Object> root) {
        JQuickGatewayConfig cfg = new JQuickGatewayConfig();

        Map<String, Object> gateway = nestedMap(root, "gateway");
        Map<String, Object> listen = nestedMap(gateway, "listen");
        cfg.setListenPort(intVal(listen, "port", DEFAULT_LISTEN_PORT));
        cfg.setListenHost(strVal(listen, "host", DEFAULT_LISTEN_HOST));
        cfg.setListenBacklog(intVal(listen, "backlog", DEFAULT_BACKLOG));
        cfg.setListenSoTimeout(intVal(listen, "so_timeout", DEFAULT_SO_TIMEOUT));
        cfg.setProbeTimeoutMs(intVal(listen, "probe_timeout_ms", cfg.getListenSoTimeout() > 0 ? cfg.getListenSoTimeout() : DEFAULT_PROBE_TIMEOUT));

        Map<String, Object> nginx = nestedMap(root, "nginx");
        Map<String, Object> nginxTarget = nestedMap(nginx, "target");
        cfg.setNginxHost(strVal(nginxTarget, "host", DEFAULT_NGINX_HOST));
        cfg.setNginxPort(intVal(nginxTarget, "port", DEFAULT_NGINX_PORT));

        Map<String, Object> other = nestedMap(root, "other");
        Map<String, Object> traffic = nestedMap(other, "traffic");
        Map<String, Object> otherTarget = nestedMap(traffic, "target");
        cfg.setOtherHost(strVal(otherTarget, "host", DEFAULT_OTHER_HOST));
        cfg.setOtherPort(intVal(otherTarget, "port", DEFAULT_OTHER_PORT));

        // ---- 增量: other.traffic.auth.* 普通TCP流量前置token鉴权 ----
        // 向后兼容: 旧配置文件完全没有 auth 段时, 鉴权默认关闭(行为与旧版完全一致);
        // 存在 auth 段但未显式写 enable 时, 按"生产默认开启(true)"处理。
        boolean hasAuthSection = traffic.get("auth") instanceof Map;
        Map<String, Object> auth = nestedMap(traffic, "auth");
        cfg.setOtherAuthEnabled(hasAuthSection && boolVal(auth, "enable", true));
        cfg.setOtherAuthTokenPrefixLen(intVal(auth, "token-prefix-len", DEFAULT_OTHER_AUTH_TOKEN_PREFIX_LEN));
        cfg.setOtherAuthTimeoutMs(intVal(auth, "timeout_ms", DEFAULT_OTHER_AUTH_TIMEOUT_MS));
        cfg.setOtherAuthValidTokens(strListVal(auth, "valid-tokens"));

        Map<String, Object> netty = nestedMap(root, "netty");
        Map<String, Object> boss = nestedMap(netty, "boss");
        Map<String, Object> worker = nestedMap(netty, "worker");
        Map<String, Object> buffer = nestedMap(netty, "buffer");
        Map<String, Object> leak = nestedMap(buffer, "leak");

        cfg.setBossThreads(intVal(boss, "threads", DEFAULT_BOSS_THREADS));
        cfg.setWorkerThreads(intVal(worker, "threads", DEFAULT_WORKER_THREADS));
        cfg.setLeakDetection(strVal(leak, "detection", DEFAULT_LEAK_DETECTION));

        return cfg;
    }

    private static void validate(JQuickGatewayConfig cfg) {
        checkPort(cfg.getListenPort(), "gateway.listen.port");
        if (cfg.getListenBacklog() <= 0) {
            throw new IllegalArgumentException("gateway.listen.backlog 必须为正整数");
        }
        checkPort(cfg.getNginxPort(), "nginx.target.port");
        checkPort(cfg.getOtherPort(), "other.traffic.target.port");
        if (cfg.getBossThreads() <= 0) {
            throw new IllegalArgumentException("netty.boss.threads 必须为正整数");
        }
        if (cfg.getWorkerThreads() < 0) {
            throw new IllegalArgumentException("netty.worker.threads 不能为负数");
        }

        // ---- 增量: 鉴权配置校验（开启时必须配置合法token，且token长度必须等于token-prefix-len）----
        if (cfg.isOtherAuthEnabled()) {
            if (cfg.getOtherAuthTokenPrefixLen() <= 0) {
                throw new IllegalArgumentException("other.traffic.auth.token-prefix-len 必须为正整数");
            }
            List<String> tokens = cfg.getOtherAuthValidTokens();
            if (tokens == null || tokens.isEmpty()) {
                throw new IllegalArgumentException(
                        "鉴权已开启(other.traffic.auth.enable=true)但未配置合法token(other.traffic.auth.valid-tokens)，"
                                + "为避免公网端口被无鉴权使用，程序拒绝启动");
            }
            for (String t : tokens) {
                int len = t.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
                if (len != cfg.getOtherAuthTokenPrefixLen()) {
                    throw new IllegalArgumentException("合法token长度必须等于 token-prefix-len("
                            + cfg.getOtherAuthTokenPrefixLen() + "B)，当前 token=" + maskToken(t) + " 长度=" + len);
                }
            }
        }
    }

    private static void checkPort(int port, String key) {
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException(key + " 取值必须在 1-65535 之间");
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> nestedMap(Map<String, Object> parent, String key) {
        if (parent == null) {
            return new java.util.HashMap<>();
        }
        Object v = parent.get(key);
        if (v instanceof Map) {
            return (Map<String, Object>) v;
        }
        return new java.util.HashMap<>();
    }

    private static int intVal(Map<String, Object> map, String key, int def) {
        Object v = map.get(key);
        if (v == null) {
            return def;
        }
        if (v instanceof Number) {
            return ((Number) v).intValue();
        }
        try {
            return Integer.parseInt(String.valueOf(v).trim());
        } catch (NumberFormatException e) {
            log.warn("配置项 {} 值非法: {}，使用默认值 {}", key, v, def);
            return def;
        }
    }

    private static String strVal(Map<String, Object> map, String key, String def) {
        Object v = map.get(key);
        if (v == null) {
            return def;
        }
        String s = String.valueOf(v).trim();
        return s.isEmpty() ? def : s;
    }

    // ==================== 增量: 鉴权配置取值辅助方法 ====================

    /** 布尔取值：支持 true/false / "true"/"false" 字符串 */
    private static boolean boolVal(Map<String, Object> map, String key, boolean def) {
        Object v = map.get(key);
        if (v == null) {
            return def;
        }
        if (v instanceof Boolean) {
            return (Boolean) v;
        }
        return Boolean.parseBoolean(String.valueOf(v).trim());
    }

    /** 字符串列表取值：用于 valid-tokens */
    private static List<String> strListVal(Map<String, Object> map, String key) {
        Object v = map.get(key);
        if (v instanceof List) {
            List<String> out = new ArrayList<>();
            for (Object o : (List<?>) v) {
                if (o != null && !String.valueOf(o).trim().isEmpty()) {
                    out.add(String.valueOf(o).trim());
                }
            }
            return out;
        }
        return new ArrayList<>();
    }

    // ==================== 环境变量覆盖（Docker 容器化支持） ====================
    // 所有运行时参数均可通过环境变量覆盖 YAML 配置，优先级: 环境变量 > YAML > 代码默认值。
    // 统一前缀 JQUICK_，例如: JQUICK_LISTEN_HOST=0.0.0.0、JQUICK_LISTEN_PORT=18080。
    private static final String ENV_PREFIX = "JQUICK_";

    private static void applyEnvOverrides(JQuickGatewayConfig cfg) {
        cfg.setListenHost(envStr("LISTEN_HOST", cfg.getListenHost()));
        cfg.setListenPort(envInt("LISTEN_PORT", cfg.getListenPort()));
        cfg.setListenBacklog(envInt("LISTEN_BACKLOG", cfg.getListenBacklog()));
        cfg.setListenSoTimeout(envInt("LISTEN_SO_TIMEOUT", cfg.getListenSoTimeout()));
        cfg.setProbeTimeoutMs(envInt("LISTEN_PROBE_TIMEOUT", cfg.getProbeTimeoutMs()));
        cfg.setNginxHost(envStr("NGINX_HOST", cfg.getNginxHost()));
        cfg.setNginxPort(envInt("NGINX_PORT", cfg.getNginxPort()));
        cfg.setOtherHost(envStr("OTHER_HOST", cfg.getOtherHost()));
        cfg.setOtherPort(envInt("OTHER_PORT", cfg.getOtherPort()));
        cfg.setOtherAuthEnabled(envBool("AUTH_ENABLE", cfg.isOtherAuthEnabled()));
        cfg.setOtherAuthTokenPrefixLen(envInt("AUTH_TOKEN_PREFIX_LEN", cfg.getOtherAuthTokenPrefixLen()));
        cfg.setOtherAuthTimeoutMs(envInt("AUTH_TIMEOUT_MS", cfg.getOtherAuthTimeoutMs()));
        List<String> tokens = envTokens("AUTH_TOKENS");
        if (tokens != null) {
            cfg.setOtherAuthValidTokens(tokens);
        }
        cfg.setBossThreads(envInt("NETTY_BOSS_THREADS", cfg.getBossThreads()));
        cfg.setWorkerThreads(envInt("NETTY_WORKER_THREADS", cfg.getWorkerThreads()));
        cfg.setLeakDetection(envStr("LEAK_DETECTION", cfg.getLeakDetection()));
    }

    private static String env(String suffix) {
        return System.getenv(ENV_PREFIX + suffix);
    }

    private static String envStr(String suffix, String def) {
        String v = env(suffix);
        return (v == null || v.trim().isEmpty()) ? def : v.trim();
    }

    private static int envInt(String suffix, int def) {
        String v = env(suffix);
        if (v == null || v.trim().isEmpty()) {
            return def;
        }
        try {
            return Integer.parseInt(v.trim());
        } catch (NumberFormatException e) {
            log.warn("环境变量 {}{} 值非法: '{}'，回退使用配置值 {}", ENV_PREFIX, suffix, v, def);
            return def;
        }
    }

    private static boolean envBool(String suffix, boolean def) {
        String v = env(suffix);
        if (v == null || v.trim().isEmpty()) {
            return def;
        }
        return Boolean.parseBoolean(v.trim());
    }

    /** 逗号分隔的合法 token 列表；未设置时返回 null 表示不覆盖 YAML */
    private static List<String> envTokens(String suffix) {
        String v = env(suffix);
        if (v == null || v.trim().isEmpty()) {
            return null;
        }
        List<String> out = new ArrayList<>();
        for (String s : v.split(",")) {
            if (!s.trim().isEmpty()) {
                out.add(s.trim());
            }
        }
        return out;
    }

    /** token掩码输出：仅前4+后2，禁止日志打印明文token */
    private static String maskToken(String t) {
        if (t == null || t.length() <= 4) {
            return "****";
        }
        return t.substring(0, 4) + "****" + t.substring(t.length() - 2);
    }
}
