# Task: Secret Encryption

## Goal

Implement encryption for secrets stored in the Tresor Application. Ensure that secrets are encrypted in the database and decrypted upon retrieval, using a unique key for each user.

## Requirements

- **Encryption at Rest:** Secrets stored in the database must be encrypted.
- **Decryption on Read:** Secrets must be decrypted when accessed by the owning user.
- **User-Specific Keys:** The encryption/decryption key must be unique for each user.
- **Web Security:** Implement basic web security if not already present (JWT not required yet).
- **Key Derivation Research:** Investigate methods for generating unique keys (e.g., using user password and salt).
- **Encryption Method Research:** Investigate suitable encryption algorithms (e.g., AES).

## Documentation Requirements (Essence Only)

- Document the research findings for key derivation and encryption methods.
- Document the implementation details (code changes, logic).
