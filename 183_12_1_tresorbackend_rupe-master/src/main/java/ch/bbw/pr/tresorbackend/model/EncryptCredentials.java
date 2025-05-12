package ch.bbw.pr.tresorbackend.model;

import jakarta.validation.constraints.NotEmpty;
import lombok.*;

/**
 * EncryptCredentials
 * @author Peter Rutschmann
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class EncryptCredentials {
   private long userId;
   private String email;
   @NotEmpty(message="encryption password id is required.")
   private String encryptPassword;
}
