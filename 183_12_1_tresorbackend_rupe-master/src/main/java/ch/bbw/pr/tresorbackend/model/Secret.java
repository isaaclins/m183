package ch.bbw.pr.tresorbackend.model;

import com.fasterxml.jackson.annotation.JsonRawValue;
import jakarta.persistence.*;
import lombok.*;

/**
 * Secret
 * @author Peter Rutschmann
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@Entity
@Table(name = "secret")
public class Secret {
   @Id
   @GeneratedValue(strategy = GenerationType.IDENTITY)
   private Long id;

   @Column(nullable = false, name="user_id")
   private Long userId;

   @Column(nullable = false, name="content")
   private String content;
}