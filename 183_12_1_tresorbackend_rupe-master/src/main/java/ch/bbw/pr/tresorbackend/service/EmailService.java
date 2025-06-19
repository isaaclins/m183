package ch.bbw.pr.tresorbackend.service;

public interface EmailService {
    void sendEmail(String to, String subject, String body);
    void sendPasswordResetEmail(String to, String firstName, String resetLink);
}