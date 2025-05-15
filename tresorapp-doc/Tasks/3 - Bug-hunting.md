# The Bug
1. Start the app
2. Create an Account
3. Log into the App
4. `Secrets` > `New Credential`
5. Input data > `Save secret`
## The Error
### Console Error
```js
Object { email: "alfred@escher.ch", password: "123" }

[NewCredential.js:25](c:/Users/Schule/temp/m183_code/183_12_2_tresorfrontend_rupe-master/src/pages/secret/NewCredential.js "View source in Debugger → c:/Users/Schule/temp/m183_code/183_12_2_tresorfrontend_rupe-master/src/pages/secret/NewCredential.js:25")  

undefined [FetchSecrets.js:14](c:/Users/Schule/temp/m183_code/183_12_2_tresorfrontend_rupe-master/src/comunication/FetchSecrets.js "View source in Debugger → c:/Users/Schule/temp/m183_code/183_12_2_tresorfrontend_rupe-master/src/comunication/FetchSecrets.js:14")  

Error posting secret: loginValues is undefined [FetchSecrets.js:38](c:/Users/Schule/temp/m183_code/183_12_2_tresorfrontend_rupe-master/src/comunication/FetchSecrets.js "View source in Debugger → c:/Users/Schule/temp/m183_code/183_12_2_tresorfrontend_rupe-master/src/comunication/FetchSecrets.js:38")  

Failed to fetch to server: Failed to save secret.
```
## Network Tab
It doesn't seem like anything gets sent.
## Debugging
1. Checkout `FetchSecrets.js`
2. Look where `loginValues` gets used
3. Added debugging in the `postSecret`-Method (`console.log("Login values in post Secret:", loginValues)`)
4. Run again -> Still undefined
5. Checkout `NewCredential.js`
6. `loginValues` gets provided to `NewCredential` as props, so we are going to add debugging there (`console.log("Login values in NewCredential:", loginValues)`)
7. Run again -> The console log in `NewCredential` gets executed twice with this content:
```js
Object { email: "alfred@escher.ch", password: "123" }
```
8. Also add debugging to `newSecret`, the final object (`console.log("FINAL: New secret in NewCredential:", newSecret)`)
```js
FINAL: New secret in NewCredential:

Object { content: {…}, kind: "credential", kindid: 1, title: "123", email: "alfred@escher.ch", encryptPassword: undefined }
```
9. I found out with `ChatGPT` that the object gets destructured but not i the way i expect it. I changed the `postSecret`-Method like this so that it will hopefully work with all secrets:
```js
export const postSecret = async (newSecret) => {
    console.log("New secret in postSecret:", newSecret);
    // Use newSecret.content, newSecret.email, etc.
}
```
10. Now we get another error, that the request didn't work:
```js
...
Initial state in NewCredential:
Object { kindid: 1, kind: "credential", userName: "", password: "", url: "" }

XHRPOST[http://localhost:8080/api/secrets](http://localhost:8080/api/secrets "http://localhost:8080/api/secrets")[HTTP/1.1 400 3ms]  

Error posting secret: encryptPassword: encryption password id is required. [FetchSecrets.js:38]
...
```
It seems like password doesn't get provided correctly. We already see that problem in every console.log before. As a simple debugging method i just set it hardcoded always to the same value `password123!`.
11. Now i get an internal server error, lets checkout the logs of the spring app:
```java
2025-05-11T18:38:55.215+02:00  WARN 27988 --- [tresorbackend] [io-8080-exec-10] o.h.engine.jdbc.spi.SqlExceptionHelper   : SQL Error: 4025, SQLState: 23000
2025-05-11T18:38:55.215+02:00 ERROR 27988 --- [tresorbackend] [io-8080-exec-10] o.h.engine.jdbc.spi.SqlExceptionHelper   : (conn=34) CONSTRAINT `secret.content` failed for `tresordb`.`secret`      
2025-05-11T18:38:55.231+02:00 ERROR 27988 --- [tresorbackend] [io-8080-exec-10] o.a.c.c.C.[.[.[/].[dispatcherServlet]    : Servlet.service() for servlet [dispatcherServlet] in context with path [] threw exception [Request processing failed: org.springframework.dao.DataIntegrityViolationException: could not execute statement [(conn=34) CONSTRAINT `secret.content` failed for `tresordb`.`secret`] [insert into secret (content,user_id) values (?,?)]; SQL [insert into secret (content,user_id) values (?,?)]; constraint [null]] with root cause

java.sql.SQLIntegrityConstraintViolationException: (conn=34) CONSTRAINT `secret.content` failed for `tresordb`.`secret`
```
I asked ChatGPT what this means: I told me that the contend doesn't seem to be what the DB is expecting. Maybe it is either null or it could be that the datatype doesn't fit.

I changed the datatype of the content from `json` to `varchar(255)` in the hopes, that it will clear things up. I got a hint from my teacher that this could be the issue.
12. Still get a server error but now another one:
```java
2025-05-11T18:44:39.745+02:00 ERROR 26904 --- [tresorbackend] [nio-8080-exec-3] o.a.c.c.C.[.[.[/].[dispatcherServlet]    : Servlet.service() for servlet [dispatcherServlet] in context with path [] threw exception [Request processing failed: org.springframework.dao.InvalidDataAccessResourceUsageException: could not execute statement [(conn=47) Data too long for column 'content' at row 1] [insert into secret (content,user_id) values (?,?)]; SQL [insert into secret (content,user_id) values (?,?)]] with root cause

java.sql.SQLSyntaxErrorException: (conn=47) Data too long for column 'content' at row 1
```
I changed the data type of content again, to `LONGTEXT` so that it doesn't have any length restrictions.
13. Yay now the secret saved, however it cant get any secrets. AAAAAAAAA!
```js
XHRPOST[http://localhost:8080/api/secrets/byemail](http://localhost:8080/api/secrets/byemail "http://localhost:8080/api/secrets/byemail")[HTTP/1.1 500 26ms]  

XHRPOST[http://localhost:8080/api/secrets/byemail](http://localhost:8080/api/secrets/byemail "http://localhost:8080/api/secrets/byemail")[HTTP/1.1 500 47ms]  

response:

Object { timestamp: "2025-05-15T17:50:47.398+00:00", status: 500, error: "Internal Server Error", path: "/api/secrets/byemail" }

[FetchSecrets.js:66](c:/Users/Schule/temp/m183_code/183_12_2_tresorfrontend_rupe-master/src/comunication/FetchSecrets.js "View source in Debugger → c:/Users/Schule/temp/m183_code/183_12_2_tresorfrontend_rupe-master/src/comunication/FetchSecrets.js:66")  

Failed to get secrets: Server response failed. [FetchSecrets.js:73](c:/Users/Schule/temp/m183_code/183_12_2_tresorfrontend_rupe-master/src/comunication/FetchSecrets.js "View source in Debugger → c:/Users/Schule/temp/m183_code/183_12_2_tresorfrontend_rupe-master/src/comunication/FetchSecrets.js:73")  

Failed to fetch to server: Failed to get secrets. [Secrets.js:25](c:/Users/Schule/temp/m183_code/183_12_2_tresorfrontend_rupe-master/src/pages/secret/Secrets.js "View source in Debugger → c:/Users/Schule/temp/m183_code/183_12_2_tresorfrontend_rupe-master/src/pages/secret/Secrets.js:25")  

response:

Object { timestamp: "2025-05-15T17:50:47.404+00:00", status: 500, error: "Internal Server Error", path: "/api/secrets/byemail" }

[FetchSecrets.js:66](c:/Users/Schule/temp/m183_code/183_12_2_tresorfrontend_rupe-master/src/comunication/FetchSecrets.js "View source in Debugger → c:/Users/Schule/temp/m183_code/183_12_2_tresorfrontend_rupe-master/src/comunication/FetchSecrets.js:66")  

Failed to get secrets: Server response failed. [FetchSecrets.js:73](c:/Users/Schule/temp/m183_code/183_12_2_tresorfrontend_rupe-master/src/comunication/FetchSecrets.js "View source in Debugger → c:/Users/Schule/temp/m183_code/183_12_2_tresorfrontend_rupe-master/src/comunication/FetchSecrets.js:73")  

Failed to fetch to server: Failed to get secrets.
```
The Backend Logs look like this:
```java
2025-05-15T19:50:42.666+02:00  INFO 12540 --- [tresorbackend] [nio-8080-exec-8] c.b.p.t.controller.UserController        : UserController.doLoginUser: Attempting login for email: alfred@escher.ch       
2025-05-15T19:50:43.020+02:00  INFO 12540 --- [tresorbackend] [nio-8080-exec-8] c.b.p.t.controller.UserController        : UserController.doLoginUser: Login successful for user ID: 8
SecretController.getSecretsByEmail EncryptCredentials(userId=0, email=alfred@escher.ch, encryptPassword=123)
SecretController.getSecretsByEmail EncryptCredentials(userId=0, email=alfred@escher.ch, encryptPassword=123)
2025-05-15T19:50:47.389+02:00 ERROR 12540 --- [tresorbackend] [nio-8080-exec-2] o.a.c.c.C.[.[.[/].[dispatcherServlet]    : Servlet.service() for servlet [dispatcherServlet] in context with path [] threw exception [Request processing failed: java.lang.RuntimeException: Error while decrypting] with root cause

javax.crypto.BadPaddingException: Given final block not properly padded. Such issues can arise if a bad key is used during decryption.
...
2025-05-15T19:50:47.389+02:00 ERROR 12540 --- [tresorbackend] [nio-8080-exec-1] o.a.c.c.C.[.[.[/].[dispatcherServlet]    : Servlet.service() for servlet [dispatcherServlet] in context with path [] threw exception [Request processing failed: java.lang.RuntimeException: Error while decrypting] with root cause

javax.crypto.BadPaddingException: Given final block not properly padded. Such issues can arise if a bad key is used during decryption.
...
```
14. I added some breakpoints to the endpoint `/api/secrets/byemail` and ran the request again
15. However the breakpoints never even got reached, I wasn't even able to get inside the `/byemail` method. Right now i am very lost because i also get different errors each time that i call the backend so i asked claude.ai for help.
16. Claude assumed that there was a data missmatch but I don't think that this the case, because I send this data:
```JSON
{"email":"alfred@escher.ch","encryptPassword":"123"}
```
And expect this data in the Backend:
```java
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class EncryptCredentials {    
	private long userId;
	private String email;
	@NotEmpty(message="encryption password id is required.")
	private String encryptPassword; 
}
```
17. After some debugging i found out that i use a hardcoded password in the frontend. After hotfixing it, everything worked as expected

TODO: Remove standard secret and always get the correct one 