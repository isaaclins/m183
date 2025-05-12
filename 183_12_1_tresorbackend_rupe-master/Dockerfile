# First part
#============

# Start with an image containing JDK 17
FROM openjdk:17-jdk-slim AS build

# Install Maven
RUN apt-get update && apt-get install -y --no-install-recommends maven git \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Setup working directory 
WORKDIR /App

# Copy the pom.xml file to the image
COPY ./pom.xml /App/

# Cache maven dependencies
RUN mvn dependency:resolve

# Copy the entire src directory to the image
COPY ./src /App/src

# Build the app
RUN mvn clean package -Dmaven.test.skip=true

# Current dir is /App
# ==> You will find the result in folder target/ 

# Second part
#============

# start with a small image
FROM alpine:latest

# add JRE 17
RUN apk add --no-cache openjdk17-jre

# Set working directory 
WORKDIR /App

# copy jar form first image to second image
COPY --from=build /App/target/*.jar /App/

# db has to start for backend
COPY wait-for-db.sh /usr/local/bin/wait-for-db.sh
RUN chmod +x /usr/local/bin/wait-for-db.sh

# Expose Port
EXPOSE 8080

ENTRYPOINT ["sh", "-c", "java -jar *.jar"]