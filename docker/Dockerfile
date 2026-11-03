# syntax=docker/dockerfile:1.7
# Shared image definition for the Spring Boot services. The jar is built by Maven
# (CI or `make images`) and passed in as MODULE; layers are extracted so dependency
# layers are cached across releases.
FROM eclipse-temurin:21-jre-alpine AS extract
ARG MODULE
WORKDIR /build
COPY ${MODULE}/target/${MODULE}-*.jar app.jar
RUN java -Djarmode=tools -jar app.jar extract --layers --destination extracted

FROM eclipse-temurin:21-jre-alpine
ARG MODULE
ARG REVISION=unknown
LABEL org.opencontainers.image.title="${MODULE}" \
      org.opencontainers.image.source="https://github.com/r0h1tb/sim-comms" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.description="Simulated comms - ${MODULE}"
RUN addgroup -S app && adduser -S -G app -u 10001 app
WORKDIR /app
COPY --from=extract /build/extracted/dependencies/ ./
COPY --from=extract /build/extracted/spring-boot-loader/ ./
COPY --from=extract /build/extracted/snapshot-dependencies/ ./
COPY --from=extract /build/extracted/application/ ./
USER 10001
ENV JAVA_OPTS="-XX:MaxRAMPercentage=75 -XX:+ExitOnOutOfMemoryError" \
    JAVA_TOOL_OPTIONS="-Djava.io.tmpdir=/tmp"
EXPOSE 8080
ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar /app/app.jar"]
