Created on 03.05.2025
# Backend
## `UserController.java`
There are two important endpoints in the `UserController.java`. Firstly the `POST: api/users/` to **register** and the `GET: api/users/login` to login.
### Current State: Register
1. Input Validation (by streaming through the fields and checking them individually, e. g. checks if a field is missing)
2. Create a User Object with first and last name, email and the hashed password (Call function `passwordService.hashPassoword`) -> Salt gets handled by BCrypt internally
3. Save User to the DB and inform the Client
### Current State: Login
1. Input Validation
2. Retrieve user by unique identifier (email)
3. Verify if the password matches (hash, salt and pepper the incoming password again and compare with the one in the DB)
4. Send Response to Client
## `PasswordEncryptionService.java`
I will list the relevant methods of this class below and explain what they do. There is also a simple helper method called `doPasswordMatch` that I left out because of its simplicity.
### `hashPassword`
1. Add a Pepper from the security config of the App to the Password
2. Generated the hashed, salted and peppered Password with `BCrypt`
### `verifyPassoword`
1. Add the Pepper to the Password
2. Get the Salt from the Password (Salt is saved in the Password) (Does Bycrpt internally)
3. Compare it with the Password in the DB with `BCrypt`
# Frontend
## `LoginUser.js`
The function gets called as soon as the user wants to log in. The functionality is as you would expect (sends the email and password to the login endpoint in the API)
## `RegisterUser.js`
Similar to `LoginUser.js` but also sends first name and last name. Afterwards a post request with this data gets sent to the register endpoint.