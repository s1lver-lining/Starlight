[AES Galois Counter Mode](https://en.wikipedia.org/wiki/Galois/Counter_Mode) is an authenticated encryption mode. For each encryption it produces a tag that can be used to verify the integrity of the message. It is considered secure and is used in TLS.

## Definition

![AES GCM](./_img/GCM-Galois_Counter_Mode_with_IV-dark.png#gh-dark-mode-only)
![AES GCM](./_img/GCM-Galois_Counter_Mode_with_IV.png#gh-light-mode-only)

## Attacks

* Forbidden attack - [CryptoHack](https://aes.cryptohack.org/forbidden_fruit/)

    When the nonce (IV) is reused in 2 different messages, an attacker can forge a tag for any ciphertext.

    [Cryptopals](https://toadstyle.org/cryptopals/63.txt) - Detailed explanation of the attack.

    [GitHub](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/gcm/forbidden_attack.py) - Implementation of the attack.

    [GitHub (Crypton)](https://github.com/ashutosh1206/Crypton/tree/master/Authenticated-Encryption/AES-GCM/Attack-Forbidden) - Summary of the attack.

    [This custom python script](./Tools/forbidden_attack.py) gives an example implementation of the attack.