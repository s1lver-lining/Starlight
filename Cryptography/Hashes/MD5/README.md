[MD5](https://en.wikipedia.org/wiki/MD5) (Message Digest Algorithm 5) is a historically significant cryptographic hash function. It is no longer considered secure as it has been found to suffer from extensive weaknesses.


* MD5 collisions

    MD5 is know to have collision issues. For exemple, it is very easy to find two byte strings with a given prefix that have the same MD5 hash.

    See these github repositories for more information:
    - [collisions](https://github.com/corkami/collisions)
    - [hashclash](https://github.com/cr-marcstevens/hashclash)

* MD5 length extension - [GitHub](https://github.com/iagox86/hash_extender)

    MD5 is also vulnerable to length extension attacks. This means that if you have the hash of a message, you can easily compute the hash of a message that has the original message as a prefix.

    See this [GitHub repository](https://github.com/iagox86/hash_extender) for more information.