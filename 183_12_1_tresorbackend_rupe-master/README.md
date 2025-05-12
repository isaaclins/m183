# Backend for the _secret tresor application_

This is the backend is a Java Springboot application.

It can be used by API-calls.

The data's are stored in a database.

### information about database

prepare a database server and the database used by the application<br>
see [tresordb.sql](tresordb.sql) for an example database<br>
see [application.properties](src/main/resources/application.properties) about database access

## Requests examples

see [UserRequests.http](httprequest/UserRequests.http)<br>
see [SecretRequests.http](httprequest/SecretRequests.http)

## Environment variables

see [application.properties](src/main/resources/application.properties)

## Build image

see Dockerfile

```Bash
docker build -t tresorbackendimg .
```



## Start container local

```Bash
docker run -p 8080:8080 --name tresorbackend tresorbackendimg
```

(c) P.Rutschmann
