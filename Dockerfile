# 使用官方 OpenJDK 运行时环境镜像
FROM openjdk:21-jdk-slim

# 指定工作目录 所有操作将在 /app 目录下执行
WORKDIR /app

ARG jar_file=spring_sso_saml-0.0.1-SNAPSHOT.jar

# 复制 JAR 文件到镜像 复制本地 target/myapp.jar 到容器 /app.jar
COPY target/${jar_file} app.jar

# 运行 JAR 文件
ENTRYPOINT ["java", "-jar", "app.jar"]
EXPOSE 8080
