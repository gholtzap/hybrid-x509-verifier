FROM maven:3.9.11-eclipse-temurin-21@sha256:6fdc855a6ed81d288ca7ca37ac6ff5e9308b612485c0801d70b25a858c83d237 AS build
WORKDIR /source
COPY pom.xml ./
ARG BC_VERSION=1.85
RUN mvn -q -DskipTests -Dbc.version="$BC_VERSION" dependency:go-offline
COPY src ./src
RUN mvn -q -DskipTests -Dbc.version="$BC_VERSION" package

FROM eclipse-temurin:21-jre@sha256:8cef5fc7bebe421363ab543a2f4db5caf7d119d8db67d56b0f56c485d2de4d55
COPY --from=build /source/target/adapter.jar /adapter.jar
ENTRYPOINT ["java", "-jar", "/adapter.jar"]
