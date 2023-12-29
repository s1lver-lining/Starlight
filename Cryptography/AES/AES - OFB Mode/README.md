[AES Output FeedBack](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Output_feedback_(OFB)) is an unusual stream cipher. It has no real benefits these days over CTR mode. Indeed CTR can be computed in parallel and allows random access in the ciphertext whereas OFB cannot.

<!--image -->
![OFB Encryption](./_img/601px-OFB_encryption.png#gh-light-mode-only)
![OFB Encryption](./_img/601px-OFB_encryption-dark.png#gh-dark-mode-only)
![OFB Decryption](./_img/601px-OFB_decryption.png#gh-light-mode-only)
![OFB Decryption](./_img/601px-OFB_decryption-dark.png#gh-dark-mode-only)