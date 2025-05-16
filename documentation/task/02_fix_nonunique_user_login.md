# Task: Fix NonUniqueResultException during User Login

## Description

The application was throwing a `NonUniqueResultException` when a user tried to log in, particularly after new users were created. This indicated that the database query for finding a user by email was returning multiple results instead of a unique one.

## Requirements Met

- Identify the cause of the `NonUniqueResultException`.
- Implement a fix in the backend Java Spring application to handle cases where duplicate emails might exist in the database, preventing the login process from failing.
- Update the relevant repository and service layers.
- Provide recommendations for ensuring data integrity regarding unique email addresses.

## Implementation Details

- **File:** `183_12_1_tresorbackend_rupe-master/src/main/java/ch/bbw/pr/tresorbackend/repository/UserRepository.java`
  - Changed method signature from `Optional<User> findByEmail(String email)` to `User findFirstByEmail(String email)`.
- **File:** `183_12_1_tresorbackend_rupe-master/src/main/java/ch/bbw/pr/tresorbackend/service/impl/UserServiceImpl.java`
  - Updated the `findByEmail` method to call `userRepository.findFirstByEmail(email)` and removed `Optional` handling.

The solution documentation (`documentation/solution/02_fix_nonunique_user_login.md`) contains a detailed explanation, code diffs, and a sequence diagram.
