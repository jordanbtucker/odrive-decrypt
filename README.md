# odrive-decrypt

Decrypts files encrypted by oDrive.

This is a work in progress. oDrive has yet to divulge critical information
regarding the encryption process.

Please follow the discussions on oDrive's forum.

- [Encryption questions: Key storage, decryption process, and others][1]
- [Decrypting Data without odrive][2]

## Required information

- [x] File encryption process: [Source][3]
  - [x] Encryption algorithm: AES-256-CBC
    - [x] Key size: 256-bits
    - [x] IV size: 128-bits
  - [x] KDF: PBKDF2
    - [x] Salt size: 64-bits
    - [ ] Iterations
    - [x] Digest algorithm: HMAC-SHA256
  - [x] Plaintext format:
    - [x]: File contents
    - [x]: SHA256 hash of file contents
  - [x] Encrypted file format:
    - [x] Version info size: 8-bits
    - [x] Salt
    - [x] IV
    - [x] Ciphertext
- [ ] File and folder name encryption process

[1]: https://forum.odrive.com/t/encryption-questions-key-storage-decryption-process-and-others/2094
[2]: https://forum.odrive.com/t/decrypting-data-without-odrive/1061
[3]: https://forum.odrive.com/t/encryption-questions-key-storage-decryption-process-and-others/2094/2
