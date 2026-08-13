# ============================================================================
#  Stage 1: build —— Maven + JDK 8，产出可执行 fat-jar
# ============================================================================
FROM maven:3.9-eclipse-temurin-8 AS builder
WORKDIR /build

# 先拷贝 pom.xml 再拷贝源码，借助 Docker 层缓存加速重复构建
COPY pom.xml .
COPY src ./src
RUN mvn -q -DskipTests package

# ============================================================================
#  Stage 2: runtime —— 仅 JRE 基础镜像（不含编译工具，镜像更小更安全）
#
#  容器化约定（务必遵守）：
#   1. 不写 EXPOSE —— 镜像内不固化任何端口，端口完全由运行时 docker run -p 决定
#   2. 不硬编码 IP/端口 —— 镜像内置 gateway.yaml 仅为占位默认值，所有关键参数
#      通过 JQUICK_* 环境变量或挂载的自定义 yaml 传入
#      （优先级: 环境变量 > YAML > 代码默认值）
# ============================================================================
FROM eclipse-temurin:8-jre-jammy

LABEL org.opencontainers.image.title="jquick-hub" \
      org.opencontainers.image.description="Netty4 single-port protocol-sniffing TCP gateway (HTTP/HTTPS -> Nginx, Other -> target)"

WORKDIR /app

# maven-shade-plugin 的 finalName 为 tcp-gateway，产物即可执行 fat-jar
COPY --from=builder /build/target/tcp-gateway.jar /app/tcp-gateway.jar

# 内置默认配置文件（占位，无硬编码 IP/端口），可用 -v 挂载覆盖或由环境变量覆盖
COPY docker/gateway.yaml /app/gateway.yaml

ENV TZ=Asia/Shanghai \
    LANG=C.UTF-8

# 入口: java -jar，默认加载 /app/gateway.yaml
# 覆盖配置路径: docker run <image> /custom/path/gateway.yaml
ENTRYPOINT ["java", "-jar", "/app/tcp-gateway.jar"]
CMD ["/app/gateway.yaml"]
