# Solution: Password Hashing Research

## 1. Research Summary

Based on research into secure password storage practices for Java Spring Boot applications, the following points are essential:

### 1.1. Hashing Algorithms

- **Requirement:** Passwords must **never** be stored in plaintext. One-way hashing functions are required.
- **Problem with Simple Hashes (e.g., SHA-256):** While one-way, simple cryptographic hashes are too fast to compute on modern hardware, making them vulnerable to brute-force and rainbow table attacks even with salt.
- **Solution: Adaptive Hash Functions:** Algorithms like `BCrypt`, `SCrypt`, and `Argon2` are recommended. They are designed to be computationally intensive (slow) and often incorporate memory usage requirements.
  - **BCrypt:** Widely supported, mature, and available directly in Spring Security (`BCryptPasswordEncoder`). It automatically handles salting.
  - **SCrypt:** Also strong, designed to be memory-hard, resisting custom hardware attacks. Supported by Spring Security (`SCryptPasswordEncoder`).
  - **Argon2:** Winner of the Password Hashing Competition (2015), considered the strongest. It offers resistance to various attacks (GPU cracking, side-channel). Spring Security supports it (`Argon2PasswordEncoder`) but requires an additional dependency (e.g., BouncyCastle).
- **Choice:** `BCrypt` is chosen for this project due to its good balance of security, widespread adoption, and ease of integration with Spring Security without extra dependencies.

### 1.2. Salt

- **Purpose:** A unique, randomly generated value added to each password before hashing. It prevents attackers from using precomputed rainbow tables, as the hash becomes unique even for identical passwords.
- **Implementation:** Modern adaptive hash functions like `BCrypt` generate and manage salts automatically. The salt is typically stored as part of the resulting hash string (e.g., `$2a$10$dXJ3SW6...`). No separate storage or manual handling is needed when using `BCryptPasswordEncoder`.

### 1.3. Pepper

- **Purpose:** A secret value, known only to the server (not stored with the user's data), added to the password _before_ hashing. If the database (including hashes and salts) is compromised, the pepper adds an additional barrier, as the attacker still needs the secret pepper to brute-force passwords effectively.
- **Implementation:** Can be implemented by concatenating a secret string (stored securely in server configuration like `application.properties` or environment variables) to the plaintext password before passing it to the `BCryptPasswordEncoder`'s `encode` or `matches` methods.

### 1.4. Spring Security Integration

- Spring Security provides the `PasswordEncoder` interface and implementations like `BCryptPasswordEncoder`.
- A `PasswordEncoder` bean needs to be configured (typically `BCryptPasswordEncoder`).
- This bean is then used by the `AuthenticationProvider` (e.g., `DaoAuthenticationProvider`) for matching passwords during login and injected into services/controllers for encoding passwords during registration.
- Spring Security's `DelegatingPasswordEncoder` allows supporting multiple hashing algorithms simultaneously and migrating passwords over time.

## 2. Next Steps

Implement password hashing in the backend using `BCryptPasswordEncoder` and incorporate a Pepper retrieved from application configuration.
