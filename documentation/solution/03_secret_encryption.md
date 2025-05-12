# Solution: Secret Encryption Implementation

This document outlines the implementation details for encrypting secrets within the Tresor application, fulfilling the requirements outlined in `documentation/task/03_secret_encryption.md`.

## 1. Overview

The goal was to ensure secrets are stored encrypted in the database and decrypted only when accessed by the authorized user, using a key unique to that user. We implemented this using AES-GCM encryption, with the key derived from the user's login password and a unique salt stored per user, using PBKDF2.

## 2. Backend Changes (`183_12_1_tresorbackend_rupe-master`)

### 2.1. Security Configuration (`SecurityConfig.java`)

Basic Spring Security HTTP configuration was added to protect endpoints.

- **What:** Enabled `EnableWebSecurity`, defined a `SecurityFilterChain` bean.
- **How:**

  - Configured `authorizeHttpRequests` to permit unauthenticated POST requests to `/api/users` (for registration) and `/public/**`, `/error`, while requiring authentication (`authenticated()`) for all other requests.
  - Enabled form login (`formLogin`) and basic authentication (`httpBasic`).
  - Disabled CSRF (`csrf().disable()`) for simplicity in this API context. Note: Should be enabled with proper token handling in production.

- **Code Snippet (`SecurityConfig.java`):**

  '''java
  @Configuration
  @EnableWebSecurity // Enable Spring Security's web security support
  public class SecurityConfig {

      @Bean
      public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
          http
                  .authorizeHttpRequests(authorizeRequests ->
                          authorizeRequests
                                  .requestMatchers(HttpMethod.POST, "/api/users").permitAll() // Allow user registration
                                  .requestMatchers("/public/**", "/error").permitAll() // Allow access to public resources and error pages
                                  .anyRequest().authenticated() // Require authentication for any other request
                  )
                  .formLogin(Customizer.withDefaults()) // Enable form-based login
                  .httpBasic(Customizer.withDefaults()) // Enable basic authentication (optional)
                  .csrf(csrf -> csrf.disable()); // Disable CSRF for simplicity
          return http.build();
      }

      // Existing PasswordEncoder bean remains
      @Bean
      public PasswordEncoder passwordEncoder() {
          return new BCryptPasswordEncoder();
      }

  }
  '''

### 2.2. User Entity (`model/User.java`)

Added a field to store a unique salt for each user.

- **What:** Added a `salt` field of type `String`.
- **How:** Annotated with `@Column` to map to the database. The salt is stored as a Base64 encoded string.

- **Code Snippet (`User.java`):**

  '''java
  // ... other fields ...
  @Column(nullable = false)
  private String password;

  @Column(nullable = false, unique = true, name="salt") // Store as Base64 encoded string
  private String salt;
  '''

### 2.3. User Controller (`controller/UserController.java`)

Modified the user creation process to generate and store the salt.

- **What:** Updated the `createUser` method.
- **How:**

  - Used `SecureRandom` to generate 16 random bytes for the salt.
  - Encoded the salt bytes to a Base64 string using `Base64.getEncoder()`.
  - Set the generated salt string on the `User` object before calling `userService.createUser()`.

- **Code Snippet (`UserController.java` - `createUser` method):**

  '''java
  // ... inside createUser method ...
  // Generate Salt
  SecureRandom random = new SecureRandom();
  byte[] saltBytes = new byte[16];
  random.nextBytes(saltBytes);
  String salt = Base64.getEncoder().encodeToString(saltBytes);

  // transform registerUser to user
  User user = new User(
  null,
  registerUser.getFirstName(),
  registerUser.getLastName(),
  registerUser.getEmail(),
  passwordEncoder.encode(registerUser.getPassword()),
  salt // Set the generated salt
  );

  User savedUser = userService.createUser(user);
  // ... rest of method ...
  '''

### 2.4. Encryption Service (`service/EncryptionService.java`)

Created a dedicated service for handling encryption and decryption logic.

- **What:** Implemented `EncryptionService` class.
- **How:**
  - Uses AES in GCM mode (`AES/GCM/NoPadding`) which provides authenticated encryption.
  - Uses PBKDF2 (`PBKDF2WithHmacSHA256`) to derive a 256-bit AES key from the user's provided password and their unique Base64 decoded salt. A high iteration count (65536) is used for security.
  - **Encryption:**
    - Generates a random 12-byte Initialization Vector (IV) for each encryption operation.
    - Encrypts the data using the derived key and the IV.
    - Prepends the IV to the ciphertext.
    - Encodes the combined IV + ciphertext using Base64 for storage as a String.
  - **Decryption:**
    - Decodes the Base64 input string.
    - Extracts the IV from the beginning of the decoded data.
    - Extracts the actual ciphertext.
    - Derives the same AES key using the password and salt.
    - Decrypts the ciphertext using the key and extracted IV.
    - Returns the plaintext string.
  - Includes basic error handling, throwing `RuntimeException` on failure (consider custom exceptions for production).

### 2.5. Secret Controller (`controller/SecretController.java`)

Integrated `EncryptionService` to replace the old `EncryptUtil` and secured endpoints.

- **What:** Refactored `createSecret`, `getSecretsByUserId`, `getSecretsByEmail`, `updateSecret`, and `deleteSecret` methods.
- **How:**

  - Injected `EncryptionService`.
  - Removed usage of `EncryptUtil` (The utility class itself was also deleted).
  - Modified methods to call `encryptionService.encrypt` or `encryptionService.decrypt`.
  - These methods now expect the user's _login password_ in the `encryptPassword` field of the `NewSecret` or `EncryptCredentials` DTOs.
  - The user's `salt` is retrieved from the `User` object (fetched via `UserService`) and passed to the encryption/decryption methods.
  - Added basic checks (e.g., user existence, secret ownership) and improved error handling responses.
  - The `updateSecret` method includes a check to ensure the provided password can decrypt the _existing_ secret before allowing the update.
  - The `deleteSecret` method was changed to require `EncryptCredentials` in the request body. It now verifies that the secret belongs to the user and that the provided password is correct (by attempting decryption) before deleting the secret.

- **Code Snippet (`SecretController.java` - Example: createSecret):**
  '''java
  // ... inside createSecret method after validation ...
  User user = userService.findByEmail(newSecret.getEmail());
  if (user == null) { /_ handle user not found _/ }

  try {
  String encryptedContent = encryptionService.encrypt(
  newSecret.getContent().toString(),
  newSecret.getEncryptPassword(), // User's login password from request
  user.getSalt() // User's salt from DB
  );
  Secret secret = new Secret(null, user.getId(), encryptedContent);
  secretService.createSecret(secret);
  // ... success response ...
  } catch (Exception e) {
  // ... error response ...
  }
  '''

- **Code Snippet (`SecretController.java` - Example: getSecretsByUserId):**
  '''java
  // ... inside getSecretsByUserId method ...
  User user = userService.getUserById(credentials.getUserId());
  if (user == null) { /_ handle user not found _/ }
  List<Secret> secrets = secretService.getSecretsByUserId(credentials.getUserId());
  if (secrets.isEmpty()) { /_ return empty list _/ }

  try {
  for (Secret secret : secrets) {
  String decryptedContent = encryptionService.decrypt(
  secret.getContent(),
  credentials.getEncryptPassword(), // User's login password from request
  user.getSalt() // User's salt from DB
  );
  secret.setContent(decryptedContent);
  }
  // ... success response with decrypted secrets ...
  } catch (Exception e) {
  // ... error response (e.g., wrong password) ...
  }
  '''

- **Code Snippet (`SecretController.java` - Example: deleteSecret):**
  '''java
  @DeleteMapping("{id}")
  public ResponseEntity<String> deleteSecret(
  @PathVariable("id") Long secretId,
  @RequestBody EncryptCredentials credentials) { // Requires credentials

        // 1. Find user
        User user = userService.findByEmail(credentials.getEmail());
        // ... handle user not found ...

        // 2. Find secret
        Secret secretToDelete = secretService.getSecretById(secretId);
        // ... handle secret not found ...

        // 3. Verify ownership
        if (!secretToDelete.getUserId().equals(user.getId())) {
            // ... handle forbidden ...
        }

        // 4. Verify password
        try {
            encryptionService.decrypt(
                    secretToDelete.getContent(),
                    credentials.getEncryptPassword(),
                    user.getSalt()
            );
        } catch (Exception e) {
             // ... handle unauthorized (wrong password) ...
        }

        // 5. Delete secret
        try {
            secretService.deleteSecret(secretId);
            return new ResponseEntity<>("{\"message\": \"Secret successfully deleted!\"}", HttpStatus.OK);
        } catch (Exception e) {
             // ... handle internal server error ...
        }

  }
  '''

### 2.6. Secret Entity (`model/Secret.java`)

No changes were needed here. The `content` field remains a `String` to store the Base64 encoded result from `EncryptionService`.

## 3. Frontend Changes (`183_12_2_tresorfrontend_rupe-master`)

Significant changes were made to the frontend to integrate with the updated backend encryption and to fulfill the task of type-dependent visual representation of secrets.

### 3.1. API Communication (`comunication/FetchSecrets.js`)

- **Password Handling:** The existing `postSecret` and `getSecretsforUser` functions already passed `loginValues.email` and `loginValues.password` (as `encryptPassword`) which aligns with the backend changes. No changes were needed here for those functions regarding password data.
- **New `deleteSecret` Function:**

  - **What:** Added a new asynchronous function `deleteSecret({ secretId, loginValues })`.
  - **How:** This function makes a `DELETE` request to `${API_URL}/secrets/${secretId}`. Crucially, it sends a JSON body containing `{ email: loginValues.email, encryptPassword: loginValues.password }` to allow the backend to verify the user and password before deletion. It includes error handling for the fetch call.

- **Code Snippet (`FetchSecrets.js` - `deleteSecret` function):**
  '''javascript
  export const deleteSecret = async ({ secretId, loginValues }) => {
  // ... (API URL construction) ...
  try {
  const response = await fetch(`${API_URL}/secrets/${secretId}`, {
  method: 'DELETE',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
  email: loginValues.email,
  encryptPassword: loginValues.password
  })
  });
  // ... (response handling and error checking) ...
  } catch (error) {
  // ... (error logging and re-throwing) ...
  }
  };
  '''

### 3.2. Secret Display and Management (`pages/secret/Secrets.js`)

This component was heavily refactored to handle the new display requirements and deletion functionality.

- **What:**
  - Added a "Delete" button for each secret.
  - Implemented type-dependent display for secret content.
  - Improved loading and error message states.
- **How:**

  - **Deletion:**
    - A `handleDelete` asynchronous function was added. It calls `deleteSecret` from `FetchSecrets.js`.
    - Upon successful deletion, it filters the deleted secret out of the local `secrets` state for an immediate UI update.
    - A `window.confirm` dialog is used for basic delete confirmation.
    - Loading and error states are managed during the delete operation.
  - **Type-Dependent Display (`SecretContent` component):**
    - A new sub-component `SecretContent({ content })` was created.
    - It parses the `content` string (which is the decrypted JSON string from the backend).
    - A `switch` statement on `parsedContent.kind` determines how to render the secret:
      - `credential`: Displays Username, Password (with a note about visibility for demo), and URL.
      - `creditcard`: Displays Type, Number, Expiration, and CVV (with a note about visibility).
      - `note`: Displays Title and Content (using `<pre>` for formatting).
      - A default case stringifies the content if the kind is unknown or parsing fails.
  - **State Management:**
    - `isLoading` state was added to provide feedback during fetch and delete operations.
    - `fetchSecrets` function was memoized using `useCallback` for efficiency.
  - **UI:**
    - The table layout was adjusted slightly, removing the explicit `User ID` column (as all secrets belong to the logged-in user).
    - The Content column now uses the `SecretContent` component.
    - The Actions column contains the new Delete button.

- **Code Snippet (`Secrets.js` - `SecretContent` component):**
  '''javascript
  const SecretContent = ({ content }) => {
  let parsedContent;
  try {
  parsedContent = JSON.parse(content);
  } catch (e) { /_ ... error handling ... _/ return <pre>{content}</pre>; }

      switch (parsedContent.kind) {
          case 'credential':
              return (
                  <div>
                      <strong>Username:</strong> {parsedContent.userName}<br />
                      <strong>Password:</strong> {parsedContent.password} {/* ... */}<br />
                      <strong>URL:</strong> {parsedContent.url}
                  </div>
              );
          case 'creditcard':
              // ... similar rendering for credit card details ...
          case 'note':
              // ... similar rendering for note details ...
          default:
              return <pre>{JSON.stringify(parsedContent, null, 2)}</pre>;
      }

  };
  '''

- **Code Snippet (`Secrets.js` - `handleDelete` function):**
  '''javascript
  const handleDelete = async (secretId) => {
  if (!window.confirm(`Are you sure you want to delete secret ${secretId}?`)) return;
  // ... (set loading and error states) ...
  try {
  await deleteSecret({ secretId, loginValues });
  setSecrets(currentSecrets => currentSecrets.filter(secret => secret.id !== secretId));
  // ... (log success) ...
  } catch (error) {
  // ... (set error message) ...
  } finally {
  // ... (set loading to false) ...
  }
  };
  '''

## 4. Security Considerations & Next Steps

- **Password Handling:** The requirement for the frontend to send the user's login password repeatedly is not ideal. Alternatives like deriving a session-specific key on login or prompting for the password only for sensitive actions could be explored.
- **Insecure Endpoints:**
  - The `getAllSecrets` endpoint remains insecure. It retrieves all secrets (encrypted) without user context or password verification. It should ideally be removed or restricted to administrative roles with a different mechanism for potential decryption/management if required.
- **Old Utility:** The `EncryptUtil` class has been removed.
- **Error Handling:** Use more specific exceptions than `RuntimeException` in `EncryptionService` for production.
- **Visual Representation:** The additional task ("Zusatz Aufgabe") regarding visual representation based on secret type in the frontend has been implemented.

This implementation provides the core requirement of user-specific, password-based encryption for secrets at rest, with basic security configuration and password checks on update/delete operations. The frontend now correctly sends necessary credentials and displays secrets based on their type.
