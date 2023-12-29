# Script adapted from this implementation of the Fluhrer-Mantin-Shamir attack:
# https://github.com/jackieden26/FMS-Attack/blob/master/keyRecover.py

from Crypto.Cipher import ARC4
from Crypto.Util.number import long_to_bytes



# Helper function, which swaps two values in the box.
def swapValueByIndex(box, i, j):
    temp = box[i]
    box[i] = box[j]
    box[j] = temp

# Initialize S-box.
def initSBox(box):
    if len(box) == 0:
        for i in range(256):
            box.append(i)
    else:
        for i in range(256):
            box[i] = i

# Key schedule Algorithm (KSA) for key whose value is in unicode.
def ksa(key, box):
    j = 0
    for i in range(256):
        j = (j + box[i] + ord(key[i % len(key)])) % 256
        swapValueByIndex(box, i, j)



# MODIFY THIS FUNCTION TO MATCH YOUR ORACLE.
def oracle(ciphertext, nonce):

    cipher = ARC4.new(nonce + "hello_im_the_secret_key".encode())
    return cipher.decrypt(ciphertext)





if __name__ == "__main__":
    key = [None] * 3 # Key bytes used in the KSA.

    # Add the known key bytes to the key array. (Use when script was interrupted)
    key_string = b""
    for i in range(len(key_string)):
        key.append(ord(key_string[i]))


    # Loop to find the next key byte.
    while True:
        i_a = len(key) - 3 # index of the last known key byte
        prob = [0] * 256   # probability distribution of each byte being the next key byte
        
        for it_byte in range(256):
            key[0] = i_a+3
            key[1] = 255
            key[2] = it_byte

            j = 0
            
            box = []
            initSBox(box)

            # Simulate the S-Box after KSA initialization.
            for i in range(i_a + 3):
                j = (j + box[i] + key[i]) % 256
                swapValueByIndex(box, i, j)
                # Record the original box[0] and box[1] value.
                if i == 1:
                    original0 = box[0]
                    original1 = box[1]

            i = i_a + 3
            z = box[1]
            # if resolved condition is possibly met.
            if z + box[z] == i_a + 3:
                # If the value of box[0] and box[1] has changed, discard this possibility.
                if (original0 != box[0] or original1 != box[1]):
                    continue
                    
                nonce = long_to_bytes(key[0])+long_to_bytes(key[1])+long_to_bytes(key[2])
                output = oracle(b'\x00',nonce)
                keyStreamByte = int.from_bytes(output, "big")
                keyByte = (box.index(keyStreamByte) - j - box[i]) % 256
                prob[keyByte] += 1

            # Assume that the most hit is the correct password.
            higherPossibility = prob.index(max(prob))

        key.append(higherPossibility)
        print("\nNew key byte guessed")
        print(key)
        print("".join([chr(i) for i in key[3:]]))
