FROM maven:3.9.11-eclipse-temurin-21@sha256:6fdc855a6ed81d288ca7ca37ac6ff5e9308b612485c0801d70b25a858c83d237

WORKDIR /generator
COPY pom.xml ./
RUN mvn -q -DskipTests dependency:go-offline
COPY src ./src
RUN mvn -q -DskipTests compile

ENTRYPOINT ["mvn", "-q", "exec:java", "-Dexec.mainClass=gen.GenValid", "-Dcorpus.out=/out"]
