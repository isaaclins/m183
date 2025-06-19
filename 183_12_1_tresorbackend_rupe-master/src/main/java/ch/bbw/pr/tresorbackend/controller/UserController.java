package ch.bbw.pr.tresorbackend.controller;

import ch.bbw.pr.tresorbackend.model.ConfigProperties;
import ch.bbw.pr.tresorbackend.model.EmailAdress;
import ch.bbw.pr.tresorbackend.model.LoginUser;
import ch.bbw.pr.tresorbackend.model.RegisterUser;
import ch.bbw.pr.tresorbackend.model.ResetPasswordRequest;
import ch.bbw.pr.tresorbackend.model.User;
import ch.bbw.pr.tresorbackend.service.CaptchaService;
import ch.bbw.pr.tresorbackend.service.PasswordEncryptionService;
import ch.bbw.pr.tresorbackend.service.PasswordResetService;
import ch.bbw.pr.tresorbackend.service.PasswordValidationService;
import ch.bbw.pr.tresorbackend.service.UserService;
import ch.bbw.pr.tresorbackend.service.impl.TOTPSecretGenerator;
import ch.bbw.pr.tresorbackend.util.JwtUtil;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

/**
 * UserController
 * @author Peter Rutschmann
 */
@RestController
@RequestMapping("api/users")
public class UserController {

   private UserService userService;
   private PasswordEncryptionService passwordService;
   private PasswordValidationService passwordValidationService;
   private static final Logger logger = LoggerFactory.getLogger(UserController.class);
   private final JwtUtil jwtUtil;

   @Autowired
   public UserController(ConfigProperties configProperties, 
                        UserService userService,
                        PasswordEncryptionService passwordService,
                        PasswordValidationService passwordValidationService,
                        JwtUtil jwtUtil) {
      System.out.println("UserController.UserController: cross origin: " + configProperties.getOrigin());
      // Logging in the constructor
      logger.info("UserController initialized: " + configProperties.getOrigin());
      logger.debug("UserController.UserController: Cross Origin Config: {}", configProperties.getOrigin());
      this.userService = userService;
      this.passwordService = passwordService;
      this.passwordValidationService = passwordValidationService;
      this.jwtUtil = jwtUtil;
   }

   @Autowired
   private CaptchaService captchaService;

   @Autowired
   private PasswordResetService passwordResetService;

   // build create User REST API
   @PostMapping
   public ResponseEntity<String> createUser(@Valid @RequestBody RegisterUser registerUser, BindingResult bindingResult) {
      if (!captchaService.verifyToken(registerUser.getCaptchaToken())) {
         System.out.println("UserController.createUser: captcha failed");
         JsonObject obj = new JsonObject();
         obj.addProperty("message", "CAPTCHA verification failed");
         String json = new Gson().toJson(obj);
         return ResponseEntity.badRequest().body(json);
      }

      System.out.println("UserController.createUser: captcha passed.");

      //input validation
      if (bindingResult.hasErrors()) {
         List<String> errors = bindingResult.getFieldErrors().stream()
               .map(fieldError -> fieldError.getField() + ": " + fieldError.getDefaultMessage())
               .collect(Collectors.toList());
         System.out.println("UserController.createUser " + errors);

         JsonArray arr = new JsonArray();
         errors.forEach(arr::add);
         JsonObject obj = new JsonObject();
         obj.add("message", arr);
         String json = new Gson().toJson(obj);

         System.out.println("UserController.createUser, validation fails: " + json);
         return ResponseEntity.badRequest().body(json);
      }
      System.out.println("UserController.createUser: input validation passed");

      //password validation
      PasswordValidationService.ValidationResult validationResult = 
          passwordValidationService.validatePassword(registerUser.getPassword());
      
      if (!validationResult.valid()) {
          System.out.println("UserController.createUser: password validation failed");
          JsonArray arr = new JsonArray();
          validationResult.errors().forEach(arr::add);
          JsonObject obj = new JsonObject();
          obj.add("message", arr);
          String json = new Gson().toJson(obj);
          System.out.println("UserController.createUser, password validation fails: " + json);
          return ResponseEntity.badRequest().body(json);
      }
      System.out.println("UserController.createUser, password validation passed");

      //transform registerUser to user
      User user = new User(
            null,
            registerUser.getFirstName(),
            registerUser.getLastName(),
            registerUser.getEmail(),
            passwordService.hashPassword(registerUser.getPassword()),
            TOTPSecretGenerator.generateSecret(),
            User.Role.USER
            );

      userService.createUser(user);
      System.out.println("UserController.createUser, user saved in db");
      JsonObject obj = new JsonObject();
      obj.addProperty("answer", "User Saved");
      obj.addProperty("totpUri", String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s",
        "TresorApp", user.getEmail(), user.getMfaSecret(), "TresorApp"));
      String json = new Gson().toJson(obj);
      System.out.println("UserController.createUser " + json);
      return ResponseEntity.accepted().body(json);
   }

   // User login endpoint
   @PostMapping("/login")
   public ResponseEntity<String> doLoginUser(@RequestBody LoginUser loginUser, BindingResult bindingResult) {
      logger.info("UserController.doLoginUser: Attempting login for email: {}", loginUser.getEmail());
      
      // Input validation
      if (bindingResult.hasErrors()) {
         List<String> errors = bindingResult.getFieldErrors().stream()
               .map(fieldError -> fieldError.getField() + ": " + fieldError.getDefaultMessage())
               .collect(Collectors.toList());
         
         JsonArray arr = new JsonArray();
         errors.forEach(arr::add);
         JsonObject obj = new JsonObject();
         obj.add("message", arr);
         String json = new Gson().toJson(obj);
         
         logger.error("UserController.doLoginUser: Validation failed: {}", json);
         return ResponseEntity.badRequest().body(json);
      }
      
      // Find user by email
      User user = userService.findByEmail(loginUser.getEmail());
      if (user == null) {
         logger.warn("UserController.doLoginUser: No user found with email: {}", loginUser.getEmail());
         
         JsonObject obj = new JsonObject();
         obj.addProperty("message", "Invalid email or password");
         String json = new Gson().toJson(obj);
         
         return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(json);
      }
      
      // Verify password
      boolean passwordMatches = passwordService.verifyPassword(loginUser.getPassword(), user.getPassword());
      if (!passwordMatches) {
         logger.warn("UserController.doLoginUser: Password mismatch for user: {}", user.getEmail());
         
         JsonObject obj = new JsonObject();
         obj.addProperty("message", "Invalid email or password");
         String json = new Gson().toJson(obj);
         
         return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(json);
      }

      // Verify MFA token
      if (!user.getMfaSecret().isEmpty() && !TOTPSecretGenerator.verifyToken(user.getMfaSecret(), Integer.parseInt(loginUser.getMfaToken()))) {
         logger.warn("UserController.doLoginUser: Invalid MFA token for user: {}", user.getEmail());
         
         JsonObject obj = new JsonObject();
         obj.addProperty("message", "Invalid MFA token");
         String json = new Gson().toJson(obj);
         
         return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(json);
      }
      
      // Login successful
      logger.info("UserController.doLoginUser: Login successful for user ID: {}", user.getId());

      String token = jwtUtil.generateToken(user.getEmail(), user.getRole().name());

      JsonObject obj = new JsonObject();
      obj.addProperty("token", token);
      obj.addProperty("userId", user.getId());
      obj.addProperty("firstName", user.getFirstName());
      obj.addProperty("lastName", user.getLastName());
      obj.addProperty("email", user.getEmail());
      
      String json = new Gson().toJson(obj);
      return ResponseEntity.ok().body(json);
   }

   // build get user by id REST API
   // http://localhost:8080/api/users/1
   @GetMapping("{id}")
   public ResponseEntity<User> getUserById(@PathVariable("id") Long userId) {
      User user = userService.getUserById(userId);
      return new ResponseEntity<>(user, HttpStatus.OK);
   }

   // Build Get All Users REST API
   // http://localhost:8080/api/users
   @GetMapping
   public ResponseEntity<List<User>> getAllUsers() {
      logger.info("In GetMapping");
      List<User> users = userService.getAllUsers();
      logger.info("Got users: " + users);
      return new ResponseEntity<>(users, HttpStatus.OK);
   }

   // Build Update User REST API
   // http://localhost:8080/api/users/1
   @PutMapping("{id}")
   public ResponseEntity<User> updateUser(@PathVariable("id") Long userId,
                                          @RequestBody User user) {
      user.setId(userId);
      User updatedUser = userService.updateUser(user);
      return new ResponseEntity<>(updatedUser, HttpStatus.OK);
   }

   // Build Delete User REST API
   @DeleteMapping("{id}")
   public ResponseEntity<String> deleteUser(@PathVariable("id") Long userId) {
      userService.deleteUser(userId);
      return new ResponseEntity<>("User successfully deleted!", HttpStatus.OK);
   }


   // get user id by email
   @PostMapping("/byemail")
   public ResponseEntity<String> getUserIdByEmail(@RequestBody EmailAdress email, BindingResult bindingResult) {
      System.out.println("UserController.getUserIdByEmail: " + email);
      //input validation
      if (bindingResult.hasErrors()) {
         List<String> errors = bindingResult.getFieldErrors().stream()
               .map(fieldError -> fieldError.getField() + ": " + fieldError.getDefaultMessage())
               .collect(Collectors.toList());
         System.out.println("UserController.createUser " + errors);

         JsonArray arr = new JsonArray();
         errors.forEach(arr::add);
         JsonObject obj = new JsonObject();
         obj.add("message", arr);
         String json = new Gson().toJson(obj);

         System.out.println("UserController.createUser, validation fails: " + json);
         return ResponseEntity.badRequest().body(json);
      }

      System.out.println("UserController.getUserIdByEmail: input validation passed");

      User user = userService.findByEmail(email.getEmail());
      if (user == null) {
         System.out.println("UserController.getUserIdByEmail, no user found with email: " + email);
         JsonObject obj = new JsonObject();
         obj.addProperty("message", "No user found with this email");
         String json = new Gson().toJson(obj);

         System.out.println("UserController.getUserIdByEmail, fails: " + json);
         return ResponseEntity.badRequest().body(json);
      }
      System.out.println("UserController.getUserIdByEmail, user find by email");
      JsonObject obj = new JsonObject();
      obj.addProperty("answer", user.getId());
      String json = new Gson().toJson(obj);
      System.out.println("UserController.getUserIdByEmail " + json);
      return ResponseEntity.accepted().body(json);
   }

   @PostMapping("/request-password-reset")
   public ResponseEntity<String> requestPasswordReset(@RequestBody EmailAdress email) {
      User user = userService.findByEmail(email.getEmail());
      if (user == null) {
         return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found");
      }

      passwordResetService.createPasswordResetToken(user);
      return ResponseEntity.ok("Password reset email sent");
   }

   @PostMapping("/reset-password")
   public ResponseEntity<?> resetPassword(@RequestBody ResetPasswordRequest request) {
      try {
            passwordResetService.resetPassword(request.getToken(), request.getPassword());
            return ResponseEntity.ok("Password successfully reset");
      } catch (RuntimeException ex) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ex.getMessage());
      }
   }
}