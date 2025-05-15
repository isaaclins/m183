Created on 03.05.2025
# Backend
## `EncryptUtil.java`
Below i will list the methods of this class and explain in short what they do.
### `EncryptUtil`
1. Hash a provided `secretKey`
2. Set the first 16 bytes as `secretKeySpec` (Attribute from the Class)
### `encrypt`
1. Create a `Cipher` instance (Used to perform cryptographic operations)
2. Generate an IV (Initialization Vector (Bit like a Salt for Hashing))
3. Encrypt the provided data with the secret key and IV
4. Encode the encrypted Data in base 64 and return it
### decrypt
1. Decode encrypted data from base 64 to a byte array
2. Extract the IV and encrypted data
3. Initialize a `Ciper` instance
4. Decrypt the data
5. Return the decrypted data
## `SecretController.java`
The endpoints were already written, and i just had to make sure that the correct functions get called.
# Result
Here is the encrypted string in the database, to proof that it works:
![[Pasted image 20250511184959.png]]
