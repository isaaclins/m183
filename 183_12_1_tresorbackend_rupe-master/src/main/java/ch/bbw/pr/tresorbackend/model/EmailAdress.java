package ch.bbw.pr.tresorbackend.model;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.*;

/**
 * EmailAdress
 * @author Peter Rutschmann
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class EmailAdress {
   @NotEmpty (message="E-Mail is required.")
   private String email;
}