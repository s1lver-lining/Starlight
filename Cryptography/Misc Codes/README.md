## Tools

* `DCode` :heart: - [Website](https://www.dcode.fr)

	Support many crypto algorithms, but also some interesting tools.


* `CyberChef` - [Website](https://gchq.github.io/CyberChef/)

	Online tool to encrypt/decrypt, encode/decode, analyze, and perform many other operations on data.

* `Ciphey` - [GitHub](https://github.com/Ciphey/Ciphey)

	Automated cryptanalysis tool. It can detect the type of cipher used and try to decrypt it.
	
	Requires python version strickly less than 3.10.

	Will be replaced in the future by [Ares](https://github.com/bee-san/Ares)

## Misc Codes

Here is a list of misc codes. The goal of this section is to help recognize them and provide tools to decode them.

### One time pad based codes

* `One time pad` - [Wikipedia](https://en.wikipedia.org/wiki/One-time_pad) - `Many time pad`

	Encrypt each character with a pre-shared key. The key must be as long as the message. The key must be random and never reused.

	This can be done using XOR :

	- Encryption: c = m ^ k
	- Decryption: m = c ^ k

	If the key is repeated, it is a type of **Vigenere cipher**. [This template](./Tools/repeated_xor.ipynb) helps to crack repeated XOR keys. [`xortools`](https://github.com/hellman/xortool) can also be used for this. This is called `Many time pad`

* `Many time pad` on images/data

	When structured data is xored with a key, it is possible to find information about the plaintext using multiple ciphertexts.

	[This stackexchange question](https://crypto.stackexchange.com/questions/59/taking-advantage-of-one-time-pad-key-reuse) can help understand how the re-use of a `One time pad` can be dangerous on structured data.

* `Vigenere Cipher` - [Wikipedia](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher) 
	
	Shift cipher using a key. The key is repeated to match the length of the message.

	| Type    | Content     |
    |---------|-------------|
	| Message | HELLO WORLD |
	| Key     | ABCDE FABCD |
	| Cipher (sum)%26  | HFNLP XQEMK |

	This can be cracked using [this online tool](https://www.dcode.fr/vigenere-cipher).

* `Gronsfeld Cipher` - [Website](http://rumkin.com/tools/cipher/gronsfeld.php)

	Variant of the Vigenere cipher using a key of numbers instead of letters.


### Substitution Ciphers

Substitution ciphers are ciphers where each letter is replaced by another letter. The key is the translation table. They are vulnerable to **frequency analysis**. [This online tool](https://www.dcode.fr/substitution-cipher) can be used to decipher them (translated to the latin alphabet if needed).

* `Keyboard Shift` - [Website](https://www.dcode.fr/keyboard-shift-cipher)

	ROT but using the keyboard layout.

* `Caesar Cipher` - [Website](https://www.dcode.fr/caesar-cipher)

	Shift cipher using the alphabet. Different alphabets can also be used. Vulnerable to **frequency analysis**.

* `Atbash Cipher` - [Wikipedia](https://en.wikipedia.org/wiki/Atbash) 
	
	Shift cipher using the alphabet in reverse order.

* `Symbol Substitution Cipher` - [Website](https://www.dcode.fr/tools-list#symbols)

	Regular letters can be replaced with symbols. Those are often references to video games or films. You can either translate it to any regular letters and use a [substitution cipher solver](https://www.dcode.fr/substitution-cipher), or find it's translation table and use it.

	The most common ones are:
	| Name | Description |
	|------|-------------|
	| [Daggers Cipher](https://www.dcode.fr/daggers-alphabet) | Swords/daggers |
	| [Hylian Language (Twilight Princess)](https://www.dcode.fr/hylian-language-twilight-princess) | Lot of vertical lines |
	| [Hylian Language (Breath of the Wild)]((https://www.dcode.fr/hylian-language-breath-of-the-wild)) | Similar to uppercase Latin |
	| [Sheikah Language (Breathe of the Wild)](https://www.dcode.fr/sheikah-language) | Lines in a square |
	| [Standard Galactic Alphabet](https://www.dcode.fr/standard-galactic-alphabet) | Vertical and horizontal lines |

* Phone-Keypad

	Letters can be encoded with numbers using a phone keypad.

	| | | |
	|-|-|-|
	| **1** _ , @ | **2** A B C | **3** D E F |
	| **4** G H I | **5** J K L | **6** M N O |
	| **7** P Q R S | **8** T U V | **9** W X Y Z |
	| **\*** _ | **0** + | **#** _ |

* `Beaufourt Cipher` - [Website](https://www.dcode.fr/beaufort-cipher)

	Substitute letters to their index in the alphabet.

* `Polybius Square Cipher` - [Wikipedia](https://en.wikipedia.org/wiki/Polybius_square)

	Substitution cipher using a 5x5 grid. Each letter is presented by its coordinates on the grid, often written as a two-digit number.

	Can be cracked using simple frequency analysis. The main difficulty is to change the format of the ciphertext to make it easier to analyze.


### Transposition Ciphers

* `Transposition Cipher` - [Wikipedia](https://en.wikipedia.org/wiki/Transposition_cipher)

	Reorder the letters of the message. The key is the order of the letters.

	Example: `HELLO WORLD` with key `1,9,2,4,3,11,5,7,6,8,10` becomes `HLOLWROLED `.

	[This online tool](https://www.dcode.fr/transposition-cipher) can be used to decipher it.

### Other

* `Bacon Cipher` - [Wikipedia](https://en.wikipedia.org/wiki/Bacon%27s_cipher)

	Recognizable when the ciphertext only contains two symbols (e.g.: A and B) and the length of the ciphertext is a multiple of 5. Example: `aabbbaabaaababbababbabbba babbaabbbabaaabababbaaabb`.

	Each group of 5 symbols is a letter. It can be deciphered using [this online tool](http://rumkin.com/tools/cipher/baconian.php).

* `LC4` - [Article](https://eprint.iacr.org/2017/339.pdf) 
	
	Encryption algorithm designed to be computed by hand. [This repository](https://github.com/dstein64/LC4) provides an implementation of it.


* `Railfence Cipher` - [Wikipedia](https://en.wikipedia.org/wiki/Rail_fence_cipher)

	Transposition cipher using a key. The key is the number of rails.

	example: Hello world! with 3 rails -> Horel ol!lwd<br>
	```
	H . . . o . . . r . . .
    . e . l . _ . o . l . !
    . . l . . . w . . . d .
	```

	[This repository](https://github.com/CrypTools/RailfenceCipher) provides an implementation of it.

* `Playfair Cipher` - [Wikipedia](https://en.wikipedia.org/wiki/Playfair_cipher)

	Encrypt messages by bigrams (pairs of letters).
	[This online tool](http://bionsgadgets.appspot.com/ww_forms/playfair_ph_web_worker3.html) can help to crack it.


* `International Code of Signals` - [Wikipedia](https://en.wikipedia.org/wiki/International_Code_of_Signals) 
	
	Using flags to transmit messages. Often used on boats.	


* `EFF/DICE` - [Website](https://www.eff.org/dice)

	Generate passphrases from dice rolls. Each set of 5 dice rolls are translated to a word.

* `Base64` :heart:, `Base32`, `Base85`, `Base91` ...

	| Name | Charset | example |
	| --- | --- | --- |
	| Base64 | `A-Za-z0-9+/` | `SGVsbG8gV29ybGQh` |
	| Base32 | `A-Z2-7` | `JBSWY3DPEBLW64TMMQ======` |
	| Base85 | `A-Za-z0-9!#$%&()*+-;<=>?@^_` | `9jqo^F*bKt7!8'or``]8%F<+qT*` |
	| Base91 | `A-Za-z0-9!#$%&()*+,./:;<=>?@[]^_` | `fPNKd)T1E8K\*+9MH/@RPE.` |

	Usually decoded with python's `base64` lib, or the `base64 -d` command.


* `Base65535` - [GitHub](https://github.com/qntm/base65536)

	Each symbol (number) is encoded on 2 bytes. Consequently, when decoded to unicode, most symbols are very uncommon and also chinese characters.


* `Base41` - [GitHub](https://github.com/sveljko/base41/blob/master/python/base41.py)

	Just another data representation.


* `Enigma` - [Wikipedia](https://en.wikipedia.org/wiki/Enigma_machine)

	Machine used by the Germans during World War II to encrypt messages. Still takes a lot of time to crack today, but some tricks can be used to speed up the process.

	[404CTF WU](https://remyoudompheng.github.io/ctf/404ctf/enigma.html)


	