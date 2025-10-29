FROM maven:3.8.5-openjdk-17 AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn clean package -DskipTests

FROM openjdk:17-jdk-slim
WORKDIR /app
COPY --from=build /app/target/EventBuddyDemo-0.0.1-SNAPSHOT.jar app.jar
COPY .env .env
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar", "--server.address=0.0.0.0"]