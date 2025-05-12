package ch.bbw.pr.tresorbackend.controller;

import ch.bbw.pr.tresorbackend.model.Secret;
import ch.bbw.pr.tresorbackend.model.NewSecret;
import ch.bbw.pr.tresorbackend.model.EncryptCredentials;
import ch.bbw.pr.tresorbackend.model.User;
import ch.bbw.pr.tresorbackend.service.EncryptionService;
import ch.bbw.pr.tresorbackend.service.SecretService;
import ch.bbw.pr.tresorbackend.service.UserService;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

/**
 * SecretController
 * 
 * @author Peter Rutschmann
 */
@RestController
@RequiredArgsConstructor
@RequestMapping("api/secrets")
public class SecretController {

   private final SecretService secretService;
   private final UserService userService;
   private final EncryptionService encryptionService;

   // create secret REST API
   @CrossOrigin(origins = "${CROSS_ORIGIN}")
   @PostMapping
   public ResponseEntity<String> createSecret(@Valid @RequestBody NewSecret newSecret, BindingResult bindingResult) {
      // input validation
      if (bindingResult.hasErrors()) {
         List<String> errors = bindingResult.getFieldErrors().stream()
               .map(fieldError -> fieldError.getField() + ": " + fieldError.getDefaultMessage())
               .collect(Collectors.toList());
         System.out.println("SecretController.createSecret " + errors);

         JsonArray arr = new JsonArray();
         errors.forEach(arr::add);
         JsonObject obj = new JsonObject();
         obj.add("message", arr);
         String json = new Gson().toJson(obj);

         System.out.println("SecretController.createSecret, validation fails: " + json);
         return ResponseEntity.badRequest().body(json);
      }
      System.out.println("SecretController.createSecret, input validation passed");

      User user = userService.findByEmail(newSecret.getEmail());
      if (user == null) {
         // Handle user not found
         return ResponseEntity.status(HttpStatus.NOT_FOUND).body("{\"message\": \"User not found\"}");
      }

      try {
         // transfer secret and encrypt content using EncryptionService
         String encryptedContent = encryptionService.encrypt(
               newSecret.getContent().toString(),
               newSecret.getEncryptPassword(), // Using user's provided password
               user.getSalt());

         Secret secret = new Secret(
               null,
               user.getId(),
               encryptedContent);
         // save secret in db
         secretService.createSecret(secret);
         System.out.println("SecretController.createSecret, secret saved in db");
         JsonObject obj = new JsonObject();
         obj.addProperty("answer", "Secret saved");
         String json = new Gson().toJson(obj);
         System.out.println("SecretController.createSecret " + json);
         return ResponseEntity.accepted().body(json);
      } catch (Exception e) {
         System.err.println("SecretController.createSecret encryption failed: " + e.getMessage());
         return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"message\": \"Encryption failed\"}");
      }
   }

   // Build Get Secrets by userId REST API
   @CrossOrigin(origins = "${CROSS_ORIGIN}")
   @PostMapping("/byuserid")
   public ResponseEntity<?> getSecretsByUserId(@RequestBody EncryptCredentials credentials) {
      System.out.println("SecretController.getSecretsByUserId " + credentials);

      User user = userService.getUserById(credentials.getUserId());
      if (user == null) {
         return ResponseEntity.status(HttpStatus.NOT_FOUND).body("{\"message\": \"User not found\"}");
      }

      List<Secret> secrets = secretService.getSecretsByUserId(credentials.getUserId());
      if (secrets.isEmpty()) {
         System.out.println("SecretController.getSecretsByUserId secret isEmpty");
         // Return empty list instead of 404 if user exists but has no secrets
         return ResponseEntity.ok(secrets);
      }

      // Decrypt content
      try {
         for (Secret secret : secrets) {
            String decryptedContent = encryptionService.decrypt(
                  secret.getContent(),
                  credentials.getEncryptPassword(), // Using user's provided password
                  user.getSalt());
            secret.setContent(decryptedContent);
         }
         System.out.println("SecretController.getSecretsByUserId decrypted successfully");
         return ResponseEntity.ok(secrets);
      } catch (Exception e) {
         System.err.println("SecretController.getSecretsByUserId decryption failed: " + e.getMessage());
         // Don't expose internal errors directly, return a generic message
         return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
               .body("{\"message\": \"Decryption failed. Wrong password or corrupted data?\"}");
      }
   }

   // Build Get Secrets by email REST API
   @CrossOrigin(origins = "${CROSS_ORIGIN}")
   @PostMapping("/byemail")
   public ResponseEntity<?> getSecretsByEmail(@RequestBody EncryptCredentials credentials) {
      System.out.println("SecretController.getSecretsByEmail " + credentials);

      User user = userService.findByEmail(credentials.getEmail());
      if (user == null) {
         return ResponseEntity.status(HttpStatus.NOT_FOUND).body("{\"message\": \"User not found\"}");
      }

      List<Secret> secrets = secretService.getSecretsByUserId(user.getId());
      if (secrets.isEmpty()) {
         System.out.println("SecretController.getSecretsByEmail secret isEmpty");
         return ResponseEntity.ok(secrets);
      }

      // Decrypt content
      try {
         for (Secret secret : secrets) {
            String decryptedContent = encryptionService.decrypt(
                  secret.getContent(),
                  credentials.getEncryptPassword(), // Using user's provided password
                  user.getSalt());
            secret.setContent(decryptedContent);
         }
         System.out.println("SecretController.getSecretsByEmail decrypted successfully");
         return ResponseEntity.ok(secrets);
      } catch (Exception e) {
         System.err.println("SecretController.getSecretsByEmail decryption failed: " + e.getMessage());
         return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
               .body("{\"message\": \"Decryption failed. Wrong password or corrupted data?\"}");
      }
   }

   // Build Get All Secrets REST API
   // http://localhost:8080/api/secrets
   @CrossOrigin(origins = "${CROSS_ORIGIN}")
   @GetMapping
   public ResponseEntity<List<Secret>> getAllSecrets() {
      List<Secret> secrets = secretService.getAllSecrets();
      return new ResponseEntity<>(secrets, HttpStatus.OK);
   }

   // Build Update Secrete REST API
   // http://localhost:8080/api/secrets/1
   @CrossOrigin(origins = "${CROSS_ORIGIN}")
   @PutMapping("{id}")
   public ResponseEntity<String> updateSecret(
         @PathVariable("id") Long secretId,
         @Valid @RequestBody NewSecret newSecret,
         BindingResult bindingResult) {
      // input validation
      if (bindingResult.hasErrors()) {
         List<String> errors = bindingResult.getFieldErrors().stream()
               .map(fieldError -> fieldError.getField() + ": " + fieldError.getDefaultMessage())
               .collect(Collectors.toList());
         System.out.println("SecretController.createSecret " + errors);

         JsonArray arr = new JsonArray();
         errors.forEach(arr::add);
         JsonObject obj = new JsonObject();
         obj.add("message", arr);
         String json = new Gson().toJson(obj);

         System.out.println("SecretController.updateSecret, validation fails: " + json);
         return ResponseEntity.badRequest().body(json);
      }

      // get Secret with id
      Secret dbSecret = secretService.getSecretById(secretId);
      if (dbSecret == null) {
         System.out.println("SecretController.updateSecret, secret not found in db");
         JsonObject obj = new JsonObject();
         obj.addProperty("answer", "Secret not found in db");
         String json = new Gson().toJson(obj);
         System.out.println("SecretController.updateSecret failed:" + json);
         return ResponseEntity.badRequest().body(json);
      }
      User user = userService.findByEmail(newSecret.getEmail());
      if (user == null) {
         return ResponseEntity.status(HttpStatus.NOT_FOUND).body("{\"message\": \"User not found\"}");
      }

      // check if Secret in db belongs to the user associated with the email
      if (!dbSecret.getUserId().equals(user.getId())) {
         System.out.println("SecretController.updateSecret, not same user id");
         JsonObject obj = new JsonObject();
         obj.addProperty("answer", "Secret has not same user id");
         String json = new Gson().toJson(obj);
         System.out.println("SecretController.updateSecret failed:" + json);
         return ResponseEntity.badRequest().body(json);
      }

      // Check if the provided password can decrypt the *existing* secret before
      // updating
      try {
         encryptionService.decrypt(
               dbSecret.getContent(),
               newSecret.getEncryptPassword(), // Password from request
               user.getSalt());
      } catch (Exception e) {
         System.err.println("SecretController.updateSecret, password check failed: " + e.getMessage());
         JsonObject obj = new JsonObject();
         obj.addProperty("answer", "Password check failed. Cannot update secret.");
         String json = new Gson().toJson(obj);
         return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(json);
      }

      // Encrypt the new content and update the secret
      try {
         String encryptedContent = encryptionService.encrypt(
               newSecret.getContent().toString(),
               newSecret.getEncryptPassword(), // Password from request
               user.getSalt());

         Secret updatedSecretData = new Secret(
               secretId,
               user.getId(),
               encryptedContent);

         secretService.updateSecret(updatedSecretData); // Use the service method for updates

         System.out.println("SecretController.updateSecret, secret updated in db");
         JsonObject obj = new JsonObject();
         obj.addProperty("answer", "Secret updated");
         String json = new Gson().toJson(obj);
         System.out.println("SecretController.updateSecret " + json);
         return ResponseEntity.accepted().body(json);
      } catch (Exception e) {
         System.err.println("SecretController.updateSecret encryption failed: " + e.getMessage());
         return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
               .body("{\"message\": \"Encryption failed during update\"}");
      }
   }

   // Build Delete Secret REST API
   @CrossOrigin(origins = "${CROSS_ORIGIN}")
   @DeleteMapping("{id}")
   public ResponseEntity<String> deleteSecret(
         @PathVariable("id") Long secretId,
         @RequestBody EncryptCredentials credentials) { // Added RequestBody for password check

      System.out.println("SecretController.deleteSecret request for id: " + secretId + " with credentials.");

      // 1. Find user by email
      User user = userService.findByEmail(credentials.getEmail());
      if (user == null) {
         System.out.println("SecretController.deleteSecret, user not found with email: " + credentials.getEmail());
         return ResponseEntity.status(HttpStatus.NOT_FOUND).body("{\"message\": \"User not found\"}");
      }

      // 2. Find the secret by ID
      Secret secretToDelete = secretService.getSecretById(secretId);
      if (secretToDelete == null) {
         System.out.println("SecretController.deleteSecret, secret not found with id: " + secretId);
         return ResponseEntity.status(HttpStatus.NOT_FOUND).body("{\"message\": \"Secret not found\"}");
      }

      // 3. Verify the secret belongs to the user
      if (!secretToDelete.getUserId().equals(user.getId())) {
         System.out.println(
               "SecretController.deleteSecret, secret " + secretId + " does not belong to user " + user.getId());
         return ResponseEntity.status(HttpStatus.FORBIDDEN)
               .body("{\"message\": \"Secret does not belong to the user\"}");
      }

      // 4. Verify the password by attempting decryption
      try {
         encryptionService.decrypt(
               secretToDelete.getContent(),
               credentials.getEncryptPassword(), // Password from request
               user.getSalt());
         System.out.println("SecretController.deleteSecret, password verified for secret " + secretId);
      } catch (Exception e) {
         System.err.println(
               "SecretController.deleteSecret, password check failed for secret " + secretId + ": " + e.getMessage());
         JsonObject obj = new JsonObject();
         obj.addProperty("answer", "Password check failed. Cannot delete secret.");
         String json = new Gson().toJson(obj);
         return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(json);
      }

      // 5. Delete the secret if password is correct
      try {
         secretService.deleteSecret(secretId);
         System.out.println("SecretController.deleteSecret successfully deleted secret: " + secretId);
         return new ResponseEntity<>("{\"message\": \"Secret successfully deleted!\"}", HttpStatus.OK);
      } catch (Exception e) {
         System.err.println(
               "SecretController.deleteSecret, error during deletion for secret " + secretId + ": " + e.getMessage());
         return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
               .body("{\"message\": \"Failed to delete secret\"}");
      }
   }
}
