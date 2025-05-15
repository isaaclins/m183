package ch.bbw.pr.tresorbackend.util;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;

/**
 * EncryptUtil
 * Used to encrypt content.
 * 
 * @author Peter Rutschmann
 */
public class EncryptUtil {
   private final SecretKeySpec secretKeySpec;
   private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
   private static final int IV_LENGTH = 16;
   private static final int ITERATION_COUNT = 65536;
   private static final int KEY_LENGTH = 256;

   public EncryptUtil(String secretPassword, String saltString) {
      try {
         byte[] salt = Base64.getDecoder().decode(saltString);
         SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
         KeySpec spec = new PBEKeySpec(secretPassword.toCharArray(), salt, ITERATION_COUNT, KEY_LENGTH);
         SecretKeySpec generatedSecretKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
         this.secretKeySpec = generatedSecretKey;
      } catch (Exception e) {
         throw new RuntimeException("Error initializing secret key with PBKDF2", e);
      }
   }

   public String encrypt(String data) {
      try {
         Cipher cipher = Cipher.getInstance(ALGORITHM);
         byte[] iv = new byte[IV_LENGTH];
         new SecureRandom().nextBytes(iv); // generate random IV
         IvParameterSpec ivSpec = new IvParameterSpec(iv);

         cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);
         byte[] encrypted = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));

         // IV + encrypted data -> Base64
         byte[] encryptedWithIv = new byte[IV_LENGTH + encrypted.length];
         System.arraycopy(iv, 0, encryptedWithIv, 0, IV_LENGTH);
         System.arraycopy(encrypted, 0, encryptedWithIv, IV_LENGTH, encrypted.length);

         return Base64.getEncoder().encodeToString(encryptedWithIv);
      } catch (Exception e) {
         throw new RuntimeException("Error while encrypting", e);
      }
   }

   public String decrypt(String data) {
      try {
         byte[] encryptedWithIv = Base64.getDecoder().decode(data);
         byte[] iv = new byte[IV_LENGTH];
         byte[] encrypted = new byte[encryptedWithIv.length - IV_LENGTH];

         System.arraycopy(encryptedWithIv, 0, iv, 0, IV_LENGTH);
         System.arraycopy(encryptedWithIv, IV_LENGTH, encrypted, 0, encrypted.length);

         Cipher cipher = Cipher.getInstance(ALGORITHM);
         IvParameterSpec ivSpec = new IvParameterSpec(iv);
         cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);

         byte[] original = cipher.doFinal(encrypted);
         return new String(original, StandardCharsets.UTF_8);
      } catch (Exception e) {
         throw new RuntimeException("Error while decrypting", e);
      }
   }
}
