package ch.bbw.pr.tresorbackend.service;

import ch.bbw.pr.tresorbackend.model.User;

public interface PasswordResetService {
    void createPasswordResetToken(User user);
    void resetPassword(String token, String newPassword);
}
