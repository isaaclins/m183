# Solution: Implement Password Hashing

This document details the implementation of secure password hashing using BCrypt, Salt, and Pepper in the Tresor backend.

## 1. Dependency Management (`pom.xml`)

The core Spring Security framework dependency was added to enable authentication and security features, including `PasswordEncoder` and `UserDetailsService`.

```xml
<!-- Added -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>

<!-- Removed redundant explicit crypto dependency -->
<!--
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-crypto</artifactId>
</dependency>
-->
```

## 2. Configuration

### 2.1. Pepper (`application.properties`)

A secret pepper value was added to the configuration file. This value should be kept secret and ideally managed through environment variables or a secrets management system in production.

```properties
# Pepper for password hashing - KEEP THIS SECRET
com.example.pepper.value=aVeryStrongSecretPepperValuePleaseChange!
```

### 2.2. Password Encoder Beans (`SecurityConfig.java`)

A configuration class `SecurityConfig` was created to define the primary `PasswordEncoder` bean. It provides an instance of `BCryptPasswordEncoder`, which handles BCrypt hashing and automatic salting.

```java
package ch.bbw.pr.tresorbackend;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        // Use BCrypt with default strength (currently 10)
        return new BCryptPasswordEncoder();
    }
}
```

## 3. Pepper Integration (`PepperedPasswordEncoder.java`)

To integrate the pepper seamlessly with Spring Security's mechanisms, a decorator class `PepperedPasswordEncoder` was created. This class wraps the primary `PasswordEncoder` (BCrypt) and automatically appends the configured pepper value before encoding or matching passwords.

```java
package ch.bbw.pr.tresorbackend.service;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class PepperedPasswordEncoder implements PasswordEncoder {

    private final PasswordEncoder delegate; // Injects BCryptPasswordEncoder bean

    @Value("${com.example.pepper.value}")
    private String pepper;

    @Override
    public String encode(CharSequence rawPassword) {
        return delegate.encode(rawPassword + pepper);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return delegate.matches(rawPassword + pepper, encodedPassword);
    }
}
```

This `PepperedPasswordEncoder` is registered as a Spring `@Component`, making it the primary `PasswordEncoder` available for injection and for Spring Security's auto-configuration.

## 4. User Registration (`UserController.java`)

The `UserController` was modified:

- The placeholder `PasswordEncryptionService` dependency was removed.
- The `PepperedPasswordEncoder` bean was injected.
- The `createUser` method now uses the injected `pepperedPasswordEncoder.encode()` method to hash the password (which includes salt via BCrypt and the pepper via the decorator) before passing the `User` object to `UserService`.

```java
// ... imports ...
import ch.bbw.pr.tresorbackend.service.PepperedPasswordEncoder;
import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
@RequestMapping("api/users")
public class UserController {

   private final UserService userService;
   private final PepperedPasswordEncoder passwordEncoder; // Injected
   private final ConfigProperties configProperties;
   // ... logger ...

   @PostMapping
   public ResponseEntity<String> createUser(@Valid @RequestBody RegisterUser registerUser, BindingResult bindingResult) {
       // ... validation ...

       // Hash password using PepperedPasswordEncoder
       User user = new User(
             null,
             registerUser.getFirstName(),
             registerUser.getLastName(),
             registerUser.getEmail(),
             passwordEncoder.encode(registerUser.getPassword()) // Hashing + Salt + Pepper
             );

       User savedUser = userService.createUser(user);
       // ... response ...
   }

   // ... other methods ...
}
```

## 5. Authentication (`UserDetailsServiceImpl.java`)

A `UserDetailsServiceImpl` class was created to integrate with Spring Security's authentication process. This service implements `UserDetailsService`.

- It fetches the `User` from the `UserRepository` based on the provided username (email).
- It returns a `org.springframework.security.core.userdetails.User` object containing the username (email) and the **already hashed password** retrieved from the database.

```java
package ch.bbw.pr.tresorbackend.service.impl;

// ... imports ...
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import java.util.Collections;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + username));

        return new org.springframework.security.core.userdetails.User(
                user.getEmail(),
                user.getPassword(), // The stored hash (BCrypt + Salt + Pepper)
                Collections.emptyList()
        );
    }
}
```

Spring Security's `DaoAuthenticationProvider` (auto-configured) will use this service to load the user and the `PepperedPasswordEncoder` bean to compare the submitted password (with pepper automatically added by the encoder) against the stored hash during login attempts.

## 6. Cleanup

- The placeholder `PasswordEncryptionService.java` was deleted.
- Hashing logic previously added to `UserServiceImpl.java` was removed, as hashing now occurs in the `UserController` before the service call.
