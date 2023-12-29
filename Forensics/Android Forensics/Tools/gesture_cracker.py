import itertools
import sys
from hashlib import sha1

def sha1_crack(target_hash:str):
    """
    Cracks the SHA1 hash of a gesture.key file and prints the gesture as a string of integers

    Args:
        target_hash (str): The SHA1 hash of the gesture.key file in hexadecimal
    """

    # List of all possible characters
    gesture_chars = ["\x00","\x01","\x02","\x03","\x04","\x05","\x06","\x07","\x08","\x09"]
    print ("hash = {}".format(target_hash))

    # Iterate through all possible lengths of the gesture
    for i in range(2, 10):

        # Iterate through all possible permutations of the gesture with the given length
        permutations = [(''.join(p)).encode('utf-8') for p in itertools.permutations(gesture_chars, i)]
        for j in permutations:
            current_hash = sha1(j).hexdigest()
            if target_hash == current_hash:

                # Print the gesture as a string of integers
                print ("gesture = {}".format(j.hex()[1::2]))

if __name__ == "__main__":

    # Parse user input
    if (len(sys.argv) < 2):
        print ("Usage: python3 gesture_cracker.py <hash in hex format>")
        print ("   or: python3 gesture_cracker.py <path to gesture.key>")
        exit()
    param1 = sys.argv[1]

    # If the parameter is a path, read the file
    if ("/" in param1):
        try:
            with open(param1, "rb") as f:
                hash = f.read().hex()
        except:
            print ("Error: " + param1 + " is not a valid file, try passing the hash directly")
            exit()
    else:
        hash = param1
    sha1_crack(hash)