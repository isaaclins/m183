package ch.bbw.pr.tresorbackend.service;

import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

@Service
public class PasswordValidationService {

    public record ValidationResult(boolean valid, List<String> errors) {
    }

    /**
     * Validates a password based on the following requirements:
     * - At least one letter, one number, and one special character
     * - At least one uppercase and one lowercase letter
     * - At least 11 characters long
     *
     * @param password The password to validate
     * @return ValidationResult with validation result and error messages if any
     */
    public ValidationResult validatePassword(String password) {
        List<String> errors = new ArrayList<>();

        // Check minimum length
        if (password.length() < 11) {
            errors.add("Password must be at least 11 characters long");
        }

        // Check for at least one lowercase letter
        if (!Pattern.compile("[a-z]").matcher(password).find()) {
            errors.add("Password must contain at least one lowercase letter");
        }

        // Check for at least one uppercase letter
        if (!Pattern.compile("[A-Z]").matcher(password).find()) {
            errors.add("Password must contain at least one uppercase letter");
        }

        // Check for at least one digit
        if (!Pattern.compile("\\d").matcher(password).find()) {
            errors.add("Password must contain at least one number");
        }

        // Check for at least one special character
        if (!Pattern.compile("[^a-zA-Z0-9]").matcher(password).find()) {
            errors.add("Password must contain at least one special character");
        }

        return new ValidationResult(errors.isEmpty(), errors);
    }
}