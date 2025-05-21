package ch.bbw.pr.tresorbackend.service.impl;

import ch.bbw.pr.tresorbackend.model.User;
import ch.bbw.pr.tresorbackend.repository.UserRepository;
import ch.bbw.pr.tresorbackend.service.UserService;

import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.Optional;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * UserServiceImpl
 * 
 * @author Peter Rutschmann
 */
@Service
@AllArgsConstructor
public class UserServiceImpl implements UserService {

   private UserRepository userRepository;

   @Override
   public User createUser(User user) {
      // Generate a salt for the new user
      SecureRandom random = new SecureRandom();
      byte[] saltBytes = new byte[16]; // 16 bytes = 128 bits, a common salt length
      random.nextBytes(saltBytes);
      user.setSalt(Base64.getEncoder().encodeToString(saltBytes));
      return userRepository.save(user);
   }

   @Override
   public User getUserById(Long userId) {
      Optional<User> optionalUser = userRepository.findById(userId);
      return optionalUser.get();
   }

   @Override
   public User findByEmail(String email) {
      return userRepository.findFirstByEmail(email);
   }

   @Override
   public List<User> getAllUsers() {
      return (List<User>) userRepository.findAll();
   }

   @Override
   public User updateUser(User user) {
      User existingUser = userRepository.findById(user.getId()).get();
      existingUser.setFirstName(user.getFirstName());
      existingUser.setLastName(user.getLastName());
      existingUser.setEmail(user.getEmail());
      User updatedUser = userRepository.save(existingUser);
      return updatedUser;
   }

   @Override
   public void deleteUser(Long userId) {
      userRepository.deleteById(userId);
   }

   @Override
   public List<String> validatePassword(String password) {
      List<String> errors = new ArrayList<>();
      if (password == null || password.length() < 8) {
         errors.add("Password must be at least 8 characters long.");
      }
      if (!Pattern.compile("[A-Z]").matcher(password).find()) {
         errors.add("Password must contain at least one uppercase letter.");
      }
      if (!Pattern.compile("[a-z]").matcher(password).find()) {
         errors.add("Password must contain at least one lowercase letter.");
      }
      if (!Pattern.compile("[0-9]").matcher(password).find()) {
         errors.add("Password must contain at least one digit.");
      }
      if (!Pattern.compile("[^a-zA-Z0-9]").matcher(password).find()) {
         errors.add("Password must contain at least one special character.");
      }
      return errors;
   }
}
