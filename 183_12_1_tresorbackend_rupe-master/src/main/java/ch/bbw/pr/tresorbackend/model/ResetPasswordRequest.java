package ch.bbw.pr.tresorbackend.model;

import lombok.Data;

@Data
public class ResetPasswordRequest {
    private String token;
    private String password;
}