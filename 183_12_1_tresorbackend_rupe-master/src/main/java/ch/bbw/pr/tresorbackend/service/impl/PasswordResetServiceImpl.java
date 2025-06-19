package ch.bbw.pr.tresorbackend.service.impl;

import ch.bbw.pr.tresorbackend.model.PasswordResetToken;
import ch.bbw.pr.tresorbackend.model.User;
import ch.bbw.pr.tresorbackend.repository.PasswordResetTokenRepository;
import ch.bbw.pr.tresorbackend.service.EmailService;
import ch.bbw.pr.tresorbackend.service.UserService;
import ch.bbw.pr.tresorbackend.service.PasswordResetService;
import ch.bbw.pr.tresorbackend.service.PasswordValidationService;
import ch.bbw.pr.tresorbackend.service.PasswordEncryptionService;
import lombok.AllArgsConstructor;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@AllArgsConstructor
public class PasswordResetServiceImpl implements PasswordResetService {

    private PasswordResetTokenRepository tokenRepository;
    private EmailService emailService;
    
    @Autowired
    private UserService userService;

    @Autowired
    private PasswordEncryptionService passwordEncryptionService;

    @Autowired
    private PasswordValidationService passwordValidationService;

    @Override
    public void createPasswordResetToken(User user) {
        String token = UUID.randomUUID().toString();
        LocalDateTime expiresAt = LocalDateTime.now().plusMinutes(15);

        PasswordResetToken passwordResetToken = new PasswordResetToken();
        passwordResetToken.setUser(user);
        passwordResetToken.setToken(token);
        passwordResetToken.setExpiresAt(expiresAt);

        tokenRepository.save(passwordResetToken);

        String resetLink = "http://localhost:3000/reset-password?token=" + token;

        emailService.sendPasswordResetEmail(user.getEmail(), user.getFirstName(), resetLink);
    }

    @Override
    public void resetPassword(String token, String password) {
        PasswordResetToken resetToken = tokenRepository.findByToken(token)
            .orElseThrow(() -> new RuntimeException("Invalid token"));

        if (resetToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new RuntimeException("Token expired");
        }

        // Validate password
        PasswordValidationService.ValidationResult result = passwordValidationService.validatePassword(password);
        if (!result.valid()) {
            throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                String.join("; ", result.errors())
            );
        }

        User user = resetToken.getUser();
        String hashedPassword = passwordEncryptionService.hashPassword(password);

        // Save updated userW
        userService.updatePassword(user.getId(), hashedPassword);

        // Invalidate token
        tokenRepository.delete(resetToken);
    }
}