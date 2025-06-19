package ch.bbw.pr.tresorbackend.service.impl;

import ch.bbw.pr.tresorbackend.service.EmailService;
import lombok.AllArgsConstructor;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;

@Service
@AllArgsConstructor
public class EmailServiceImpl implements EmailService {
    
    private JavaMailSender mailSender;
    
    @Override
    public void sendEmail(String to, String subject, String body) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            
            helper.setFrom("contact@stephanhagmann.ch");
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(body, true); // true indicates HTML content
            
            mailSender.send(message);
        } catch (MessagingException e) {
            throw new RuntimeException("Failed to send email", e);
        }
    }
    
    public void sendPasswordResetEmail(String to, String firstName, String resetLink) {
        String subject = "Reset your password";
        String htmlBody = createPasswordResetTemplate(firstName, resetLink);
        sendEmail(to, subject, htmlBody);
    }
    
    private String createPasswordResetTemplate(String firstName, String resetLink) {
    return """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Password Reset</title>
                <style>
                    body {
                        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                        line-height: 1.6;
                        color: #333;
                        max-width: 600px;
                        margin: 0 auto;
                        padding: 20px;
                        background-color: #f4f4f4;
                    }
                    .container {
                        background-color: #ffffff;
                        padding: 30px;
                        border-radius: 10px;
                        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                    }
                    .header {
                        text-align: center;
                        margin-bottom: 30px;
                    }
                    .header h1 {
                        color: #2c3e50;
                        margin: 0;
                        font-size: 28px;
                    }
                    .content {
                        margin-bottom: 30px;
                    }
                    .greeting {
                        font-size: 18px;
                        margin-bottom: 20px;
                        color: #2c3e50;
                    }
                    .message {
                        font-size: 16px;
                        margin-bottom: 25px;
                        color: #555;
                    }
                    .reset-button {
                        display: inline-block;
                        background-color: #3498db;
                        color: white;
                        padding: 15px 30px;
                        text-decoration: none;
                        border-radius: 5px;
                        font-weight: bold;
                        font-size: 16px;
                        margin: 20px 0;
                        transition: background-color 0.3s;
                    }
                    .reset-button:hover {
                        background-color: #2980b9;
                    }
                    .button-container {
                        text-align: center;
                        margin: 30px 0;
                    }
                    .footer {
                        margin-top: 30px;
                        padding-top: 20px;
                        border-top: 1px solid #eee;
                        font-size: 14px;
                        color: #888;
                        text-align: center;
                    }
                    .warning {
                        background-color: #fff3cd;
                        border: 1px solid #ffeaa7;
                        color: #856404;
                        padding: 15px;
                        border-radius: 5px;
                        margin: 20px 0;
                        font-size: 14px;
                    }
                    .link-fallback {
                        word-break: break-all;
                        color: #3498db;
                        font-size: 14px;
                        margin-top: -5px;
                        margin-bottom: 25px;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🔐 Password Reset</h1>
                    </div>
                    
                    <div class="content">
                        <div class="greeting">
                            Hi %s,
                        </div>
                        
                        <div class="message">
                            We received a request to reset your password. Click the button below to create a new password:
                        </div>
                        
                        <div class="button-container">
                            <a href="%s" class="reset-button">Reset Password</a>
                        </div>
                        
                        <div class="warning">
                            ⚠️ <strong>Important:</strong> This link will expire in 15 minutes for security reasons.
                        </div>
                        
                        <div class="message">
                            If the button doesn't work, you can copy and paste this link into your browser:
                        </div>
                        
                        <div class="link-fallback">
                            %s
                        </div>
                        
                        <div class="message">
                            If you didn't request a password reset, please ignore this email. Your password will remain unchanged.
                        </div>
                    </div>
                    
                    <div class="footer">
                        <p>This email was sent from an automated system. Please do not reply to this email.</p>
                        <p>&copy; 2025 Stephan Inc. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
            """.formatted(firstName, resetLink, resetLink);
    }
}