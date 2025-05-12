package ch.bbw.pr.tresorbackend.repository;

import ch.bbw.pr.tresorbackend.model.Secret;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

/**
 * SecretRepository
 * @author Peter Rutschmann
 */
public interface SecretRepository extends JpaRepository<Secret, Long> {
   List<Secret> findByUserId(Long userId);
}
