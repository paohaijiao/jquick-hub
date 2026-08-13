import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;

/**
 * GatewayClient —— TCP 网关"本地迷你代理"客户端（Windows / Linux 通用，零第三方依赖）。
 *
 * <p><b>用途</b>：公网网关对非 HTTP/HTTPS 流量（数据库、SSH 等）启用了"前置固定长度 magic-token 鉴权"，
 * 而 Navicat/DBeaver/psql/ssh 等原生 TCP 工具无法自定义请求头、不能修改应用层协议。
 * 本客户端运行在<b>你的本机</b>，充当本地端口转发代理：
 * <pre>
 *   数据库工具 ──连接──▶ 本机代理(监听 local.ports) ──首个数据包前拼接token──▶ 公网网关 ──剥离token──▶ 内网数据库
 * </pre>
 * 数据库工具连接本机端口即可，零修改。
 *
 * <p><b>工作原理</b>：
 * <ol>
 *   <li>每个本地端口一个监听线程，接受数据库工具等客户端连接；</li>
 *   <li>连接建立后主动连接公网网关；</li>
 *   <li>本地→网关方向：<b>第一个数据包前拼接固定长度 token（只拼一次）</b>，之后原样透传；</li>
 *   <li>网关→本地方向：原样透传；任一端断开则联动关闭另一端；</li>
 *   <li>网关不可达时静默关闭本地连接（不向工具发送任何数据，与网关鉴权失败行为一致）。</li>
 * </ol>
 *
 * <p><b>启动方式</b>（Windows 双击 start-client.bat，或命令行）：
 * <pre>
 *   javac -encoding UTF-8 GatewayClient.java
 *   java -Dfile.encoding=UTF-8 GatewayClient                          # 读取同目录 client.properties
 *   java -Dfile.encoding=UTF-8 GatewayClient -config d:\xx\client.properties
 *   java -Dfile.encoding=UTF-8 GatewayClient -ports 5236 -host x.x.x.x -port 8080 -token xxxxxxxx
 * </pre>
 *
 * <p><b>安全说明</b>：token 属于密钥，日志只输出掩码（前4+后2），明文不落日志；
 * client.properties 请按敏感文件管理（勿提交 git、控制文件权限）。
 */
public class GatewayClient {

    /** 网关连接超时（毫秒） */
    private static final int GW_CONNECT_TIMEOUT_MS = 5000;
    /** 转发缓冲大小（字节） */
    private static final int BUFFER_SIZE = 16384;

    // ---- 配置（启动时从 client.properties / 命令行参数填充）----
    private static String gwHost = "127.0.0.1";
    private static int gwPort = 8080;
    private static String tokenStr = "";
    private static byte[] TOKEN = new byte[0];
    private static List<Integer> localPorts = new ArrayList<>();

    private static final AtomicLong CONN_ID = new AtomicLong(1);

    public static void main(String[] args) throws Exception {
        // 1) 加载配置文件（-config 指定，否则找当前目录 client.properties）
        String config = findConfig(args);
        Properties p = new Properties();
        if (config != null) {
            try (InputStream in = new FileInputStream(config)) {
                p.load(in);
                System.out.println("[GatewayClient] 加载配置文件: " + config);
            }
        }
        String ports = p.getProperty("local.ports", "5236");
        gwHost = p.getProperty("gw.host", gwHost);
        gwPort = Integer.parseInt(p.getProperty("gw.port", String.valueOf(gwPort)).trim());
        tokenStr = p.getProperty("token", tokenStr);

        // 2) 命令行参数覆盖（-ports / -host / -port / -token）
        for (int i = 0; i < args.length; i++) {
            if ("-ports".equals(args[i])) ports = args[++i];
            else if ("-host".equals(args[i])) gwHost = args[++i];
            else if ("-port".equals(args[i])) gwPort = Integer.parseInt(args[++i]);
            else if ("-token".equals(args[i])) tokenStr = args[++i];
        }

        // 3) 校验
        if (tokenStr == null || tokenStr.trim().isEmpty()) {
            System.out.println("[GatewayClient] [ERROR] 未配置 token（client.properties 的 token 或 -token 参数），无法通过网关鉴权，退出。");
            System.exit(1);
        }
        TOKEN = tokenStr.trim().getBytes(java.nio.charset.StandardCharsets.UTF_8);
        localPorts = parsePorts(ports);

        // 4) 启动监听
        ExecutorService pool = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "conn-handler");
            t.setDaemon(true);
            return t;
        });
        System.out.println("==============================================================");
        System.out.println("  TCP 网关本地迷你代理 (GatewayClient)");
        System.out.println("  本地监听端口 : " + localPorts);
        System.out.println("  目标网关     : " + gwHost + ":" + gwPort);
        System.out.println("  token掩码    : " + mask(tokenStr) + " (长度 " + TOKEN.length + " 字节)");
        System.out.println("  提示: 数据库/SSH 等工具请连接上述【本地端口】");
        System.out.println("==============================================================");
        for (int port : localPorts) {
            ServerSocket ss = new ServerSocket(port, 50);
            System.out.println("[GatewayClient] 本地端口 " + port + " 已开始监听 -> 转发到网关 " + gwHost + ":" + gwPort);
            pool.submit(() -> acceptLoop(ss, pool));
        }
        // 主线程保持存活（监听线程均为 daemon）
        Thread.currentThread().join();
    }

    /** 每端口一个 accept 循环，每连接交给线程池处理（支持多工具并发连接） */
    private static void acceptLoop(ServerSocket ss, ExecutorService pool) {
        while (!ss.isClosed()) {
            try {
                Socket local = ss.accept();
                pool.submit(() -> handle(local));
            } catch (IOException e) {
                if (!ss.isClosed()) {
                    System.out.println("[GatewayClient] accept 异常: " + e.getMessage());
                }
                break;
            }
        }
    }

    /** 处理一条客户端连接：连网关 -> 双方向透传（本地→网关方向首包拼 token） */
    private static void handle(Socket local) {
        long id = CONN_ID.getAndIncrement();
        String peer = local.getRemoteSocketAddress() != null ? local.getRemoteSocketAddress().toString() : "?";
        log("[" + id + "] 新连接来自 " + peer);
        Socket gw = null;
        try {
            final Socket gwConn = new Socket();
            gwConn.connect(new InetSocketAddress(gwHost, gwPort), GW_CONNECT_TIMEOUT_MS);
            gwConn.setTcpNoDelay(true);
            local.setTcpNoDelay(true);
            gw = gwConn;
            log("[" + id + "] 已连接网关 " + gwHost + ":" + gwPort);
            Thread t1 = new Thread(() -> pipe(id, local, gwConn, true), "pipe-local2gw-" + id);
            Thread t2 = new Thread(() -> pipe(id, gwConn, local, false), "pipe-gw2local-" + id);
            t1.start();
            t2.start();
            t1.join();
            t2.join();
        } catch (IOException e) {
            // 网关不可达：静默关闭本地连接，不向工具发送任何数据（防信息泄露）
            log("[" + id + "] 连接网关失败(" + gwHost + ":" + gwPort + ")，关闭本地连接: " + e.getMessage());
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        } finally {
            closeQuietly(local);
            closeQuietly(gw);
            log("[" + id + "] 连接已关闭");
        }
    }

    /**
     * 单向透传。
     *
     * @param prependToken 仅"本地→网关"方向为 true：在<b>第一个数据包前</b>拼接固定长度 token（只拼一次）。
     *                     即使数据库工具的第一个包只是部分协议字节，token 也永远位于最前，网关按 token-prefix-len
     *                     剥离后，剩余字节即原始业务数据，顺序与内容不变。
     */
    private static void pipe(long id, Socket in, Socket out, boolean prependToken) {
        byte[] buf = new byte[BUFFER_SIZE];
        try (InputStream is = in.getInputStream(); OutputStream os = out.getOutputStream()) {
            if (prependToken) {
                int n = is.read(buf);
                if (n > 0) {
                    os.write(TOKEN, 0, TOKEN.length); // 拼接前置token
                    os.write(buf, 0, n);
                    os.flush();
                    log("[" + id + "] 首包前已拼接token(" + mask(tokenStr) + ")，转发 " + n + " 字节业务数据");
                }
                while ((n = is.read(buf)) > 0) {
                    os.write(buf, 0, n);
                }
            } else {
                int n;
                while ((n = is.read(buf)) > 0) {
                    os.write(buf, 0, n);
                }
            }
            os.flush();
        } catch (IOException ignored) {
            // 任一端关闭即结束本方向
        }
    }

    // ==================== 工具方法 ====================

    /** 解析逗号分隔的端口列表 */
    private static List<Integer> parsePorts(String ports) {
        List<Integer> list = new ArrayList<>();
        for (String s : ports.split(",")) {
            String t = s.trim();
            if (!t.isEmpty()) {
                list.add(Integer.parseInt(t));
            }
        }
        return list;
    }

    /** 查找配置文件：-config 参数优先，其次当前目录 client.properties */
    private static String findConfig(String[] args) {
        for (int i = 0; i < args.length; i++) {
            if ("-config".equals(args[i]) && i + 1 < args.length) {
                return args[i + 1];
            }
        }
        File f = new File("client.properties");
        return f.isFile() ? f.getAbsolutePath() : null;
    }

    /** token 掩码：仅显示前4+后2，禁止打印明文 */
    private static String mask(String t) {
        if (t == null || t.length() <= 4) {
            return "****";
        }
        return t.substring(0, 4) + "****" + t.substring(t.length() - 2);
    }

    private static void log(String msg) {
        System.out.println("[" + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(new Date()) + "] " + msg);
    }

    private static void closeQuietly(Socket s) {
        try {
            if (s != null) {
                s.close();
            }
        } catch (IOException ignored) {
        }
    }
}
