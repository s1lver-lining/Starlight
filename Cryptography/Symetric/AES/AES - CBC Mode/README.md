[AES Cipher Block Chaining](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)) is the most commonly used mode of operation. It uses the previous output to xor the next input.

## Definition

![CBC Encryption](./_img/CBC_encryption.png#gh-light-mode-only)
![CBC Encryption](./_img/CBC_encryption-dark.png#gh-dark-mode-only)
![CBC Decryption](./_img/CBC_decryption.png#gh-light-mode-only)
![CBC Decryption](./_img/CBC_decryption-dark.png#gh-dark-mode-only)

## Attacks

* Bit flipping attack (CPA) - [Wikipedia](https://en.wikipedia.org/wiki/Bit-flipping_attack) [CryptoHack](https://cryptohack.org/courses/symmetric/flipping_cookie/)

    If an attacker can change the ciphertext, they can also alter the plaintext because of the XOR operation in the decryption process. (Homomorphic property of XOR, used in the previous block)
    
    **If you want to change the first block of plaintext**, you need to be able to edit the IV, as the first block of plaintext is XORed with the IV. If you don't have access to it, you can try to make the target system ignore the first block and edit the remainder instead. (example: json cookie {admin=False;randomstuff=whatever} -> {admin=False;rando;admin=True} )

    [Custom exploit script](./Tools/bit-flipping-cbc.py) from this [Github gist](https://gist.github.com/nil0x42/8bb48b337d64971fb296b8b9b6e89a0d)

    [Video explanation](https://www.youtube.com/watch?v=QG-z0r9afIs)


* IV = Key - [StackExchange](https://crypto.stackexchange.com/questions/16161/problems-with-using-aes-key-as-iv-in-cbc-mode) [CryptoHack](https://aes.cryptohack.org/lazy_cbc/)

    When the IV is chosen as the key, AES becomes insecure. The Key can be leaked if you have a decryption oracle (CCA).