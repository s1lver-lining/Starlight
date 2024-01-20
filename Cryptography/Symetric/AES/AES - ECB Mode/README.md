[AES Electronic CodeBook](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB)) is the most basic mode of operation. Each block is encrypted independently of the others.  This is considered **unsecure** for most applications.

## Definition

![ECB Encryption](./_img/601px-ECB_encryption.png#gh-light-mode-only)
![ECB Encryption](./_img/601px-ECB_encryption-dark.png#gh-dark-mode-only)
![ECB Decryption](./_img/601px-ECB_decryption.png#gh-light-mode-only)
![ECB Decryption](./_img/601px-ECB_decryption-dark.png#gh-dark-mode-only)

## Attacks

* ECB Encryption Oracle padded with secret - [CryptoHack](https://cryptohack.org/courses/symmetric/ecb_oracle/)

	To leak the secret, we can use the fact that ECB mode is stateless. We can compare the output of a block containing one unknown byte of the secret with all 256 possible outputs. The block that encrypts to the correct output is the one that contains the unknown byte.

* ECB Decryption Oracle - [CryptoHack](https://cryptohack.org/courses/symmetric/ecbcbcwtf/)

	A ECB decryption oracle can simply be used as an AES block decoder. Many modes can be compromised by this oracle.
	