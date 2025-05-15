# Task: Implement Salt-Based Key Derivation for Secret Encryption

## 1. Objective

Enhance the security of the secret encryption mechanism by introducing a user-specific salt for the derivation of the AES encryption key. This will protect against pre-computation attacks (e.g., rainbow tables) on the password-to-key derivation process.

## 2. Requirements

1.  **User-Specific Salt:** Each user must have a unique, randomly generated salt.
2.  **Salt Storage:** The salt must be stored securely alongside other user details in the database.
3.  **Key Derivation:** The AES encryption key used for a user's secrets must be derived using their password and their unique salt, preferably using a standard Password-Based Key Derivation Function (PBKDF).
4.  **Integration:** The new key derivation mechanism must be integrated into all secret creation, retrieval, and update operations.

## 3. Scope

- **Backend:**
  - Modify the `User` entity to include a salt field.
  - Update `UserService` to generate and store the salt upon user creation.
  - Modify `EncryptUtil` to accept the salt and use PBKDF2 for key derivation.
  - Update `SecretController` to retrieve and use the user's salt when calling `EncryptUtil`.
  - Adjust `UserController` if necessary due to changes in `User` entity constructors.
- **Frontend:** No direct changes required for this specific task, but frontend calls will now result in more secure backend operations.
- **Database:** The `user` table schema will need to accommodate the new salt column.

## 4. Acceptance Criteria

1.  New users registered in the system have a unique salt generated and stored.
2.  Secrets created by new users are encrypted using an AES key derived via PBKDF2 with their password and unique salt.
3.  Secrets can be successfully decrypted using the same password and salt.
4.  The system remains functional for creating, reading, and updating secrets for users with salts.
5.  Login functionality (BCrypt for password hashing) remains unaffected.
6.  The implementation is documented.
