# Task: Implement Password Hashing

Implementieren Sie die Anforderungen
Dokumentieren Sie die Umsetzung (nur Essenz)

- **Goal:** Implement secure password hashing (BCrypt + Salt + Pepper) in the Tresor backend application for user registration and login, replacing any existing insecure methods.
- **Requirements:**
  - Use `BCryptPasswordEncoder` from Spring Security.
  - Integrate a server-side secret "Pepper" retrieved from application configuration.
  - Hash passwords during user registration (`POST /api/users`).
  - Ensure password verification during login uses the same hashing (BCrypt + Salt + Pepper) mechanism, integrated with Spring Security's authentication flow.
  - Configure necessary Spring beans (`PasswordEncoder`, `UserDetailsService`).
  - Remove placeholder password handling code (`PasswordEncryptionService`).
- **Files to Modify/Create:**
  - `183_12_1_tresorbackend_rupe-master/pom.xml`
  - `183_12_1_tresorbackend_rupe-master/src/main/resources/application.properties`
  - `183_12_1_tresorbackend_rupe-master/src/main/java/ch/bbw/pr/tresorbackend/SecurityConfig.java`
  - `183_12_1_tresorbackend_rupe-master/src/main/java/ch/bbw/pr/tresorbackend/service/PepperedPasswordEncoder.java` (New)
  - `183_12_1_tresorbackend_rupe-master/src/main/java/ch/bbw/pr/tresorbackend/controller/UserController.java`
  - `183_12_1_tresorbackend_rupe-master/src/main/java/ch/bbw/pr/tresorbackend/service/impl/UserDetailsServiceImpl.java` (New)
  - `183_12_1_tresorbackend_rupe-master/src/main/java/ch/bbw/pr/tresorbackend/service/PasswordEncryptionService.java` (Delete)
  - `183_12_1_tresorbackend_rupe-master/src/main/java/ch/bbw/pr/tresorbackend/service/impl/UserServiceImpl.java` (Revert)
