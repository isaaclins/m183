package ch.bbw.pr.tresorbackend.service.impl;

import ch.bbw.pr.tresorbackend.model.Secret;
import ch.bbw.pr.tresorbackend.repository.SecretRepository;
import ch.bbw.pr.tresorbackend.service.SecretService;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

/**
 * SecretServiceImpl
 * @author Peter Rutschmann
 */
@Service
@AllArgsConstructor
public class SecretServiceImpl implements SecretService {

   private SecretRepository secretRepository;

   @Override
   public Secret createSecret(Secret card) {
      return secretRepository.save(card);
   }

   @Override
   public Secret getSecretById(Long secretId) {
      Optional<Secret> optionalSecret = secretRepository.findById(secretId);
      return optionalSecret.get();
   }

   @Override
   public List<Secret> getAllSecrets() {
      return (List<Secret>) secretRepository.findAll();
   }

   @Override
   public Secret updateSecret(Secret secret) {
      Secret existingSecret = secretRepository.findById(secret.getId()).get();
      existingSecret.setUserId(secret.getUserId());
      existingSecret.setContent(secret.getContent());
      Secret updatedSecret = secretRepository.save(existingSecret);
      return updatedSecret;
   }

   @Override
   public void deleteSecret(Long secretId) {
      secretRepository.deleteById(secretId);
   }

   @Override
   public List<Secret> getSecretsByUserId(Long userId) {
      return secretRepository.findByUserId(userId);
   }

}
