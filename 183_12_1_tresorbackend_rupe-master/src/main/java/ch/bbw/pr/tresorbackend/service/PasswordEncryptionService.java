package ch.bbw.pr.tresorbackend.service;

import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCrypt;


@Service
public class PasswordEncryptionService {

   @Value("${app.security.pepper}")
   private String pepper;

   private static final int BCRYPT_COST = 12;

   /**
    * Hashes a password using bcrypt with pepper.
    */
   public String hashPassword(String password) {
      String passwordWithPepper = password + pepper;
      return BCrypt.hashpw(passwordWithPepper, BCrypt.gensalt(BCRYPT_COST));
   }

   /**
    * Verifies if a plaintext password matches the stored hashed password.
    */
   public boolean verifyPassword(String password, String hashedPassword) {
      String passwordWithPepper = password + pepper;
      return BCrypt.checkpw(passwordWithPepper, hashedPassword);
   }

   public boolean doPasswordMatch(String password, String hashedPassword) {
      return verifyPassword(password, hashedPassword);
   }
}
