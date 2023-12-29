[AES Counter Mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)) is using the AES output as a xor key. To generate the output a nonce is used, modified by a counter (concatenated, summed ...) at each block.

The main problem with this mode is that the nonce must be unique for each message, and the counter must be different for each block (it can be reset at each message). If this is not the case, the xor key will be the same for different blocks, which can compromise the encrypted message. (See the weaknesses of [XOR encryption](../README.md)

![CTR Encryption](./_img/601px-CTR_encryption_2.png#gh-light-mode-only)
![CTR Encryption](./_img/601px-CTR_encryption_2-dark.png#gh-dark-mode-only)
![CTR Decryption](./_img/601px-CTR_decryption_2.png#gh-light-mode-only)
![CTR Decryption](./_img/601px-CTR_decryption_2-dark.png#gh-dark-mode-only)
