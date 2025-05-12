package ch.bbw.pr.tresorbackend.service;

import ch.bbw.pr.tresorbackend.model.Secret;
import java.util.List;

/**
 * SecretService
 * @author Peter Rutschmann
 */
public interface SecretService {
   Secret createSecret(Secret secret);

   Secret getSecretById(Long secretId);

   List<Secret> getAllSecrets();

   Secret updateSecret(Secret secret);

   void deleteSecret(Long secretId);

   List<Secret> getSecretsByUserId(Long userId);
}
