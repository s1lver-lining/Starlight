#!/usr/bin/python3 -u
# requirements: PyCryptodome

# taken from https://gist.github.com/nil0x42/8bb48b337d64971fb296b8b9b6e89a0d 
# and modified to handle the first block and use python only

import base64
from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad

### variables to set
PLAINTEXT = b"id=12345678;name=myname;is_admin=false;mail=mymail@mail.com"
CIPHERTEXT = base64.b64decode("RlDfIOgTrnUsIZJE802+wNr0jll/3ZiM4BGHH7xMO8TF0QBkebuuychCaeDBhUP2kOJnerZm3kQoe3h9Sv12oA==")
BLOCK_SIZE = 16 # AES
PADDING_TYPE = "pkcs7" # pkcs7, x923 for ANSI_X923, iso7816 for ISO/IEC 7816-4
OLD_STR = b"false" # string to flip
NEW_STR = b"true;" # string that will replace OLD_STR

## Optional IV if the string to flip is in the first block
IV = None


print("\n[+] Infos:")
print("OLD_STR = %s" % OLD_STR)
print("NEW_STR = %s" % NEW_STR)

print("\n[+] Plaintext (%d bytes):" % len(PLAINTEXT))
print("    %s" % PLAINTEXT.hex())

if len(PLAINTEXT) != len(CIPHERTEXT):
    PLAINTEXT = pad(PLAINTEXT, block_size=BLOCK_SIZE, style=PADDING_TYPE)

print("\n[+] Plaintext [Padded with %s] (%d bytes):" % (PADDING_TYPE, len(PLAINTEXT)))
print("    %s" % PLAINTEXT.hex())

print("\n[+] Ciphertext (%d bytes):" % len(CIPHERTEXT))
print("    %s" % CIPHERTEXT.hex())

# sanity checks on inputs
assert len(PLAINTEXT) == len(CIPHERTEXT)
assert len(CIPHERTEXT) % BLOCK_SIZE == 0
assert OLD_STR in PLAINTEXT
assert len(OLD_STR) == len(NEW_STR)

# Find the first block where the string to flip is located
blocks = [PLAINTEXT[i:i + BLOCK_SIZE] for i in range(0, len(PLAINTEXT), BLOCK_SIZE)]
block_offset = 0
in_block = -1
for block_id, block in enumerate(blocks):
    if OLD_STR in block:
        in_block = block_id
        block_offset = block.find(OLD_STR)
        break

flipped_ciphertext = None
if in_block == -1:
    raise Exception("String to flip must be contained in one single block")
elif in_block == 0:
    # If the string to flip is in the first block, flip the bits in the IV
    if IV is None:
        raise Exception("IV is required to flip the first block")
    
    flipped_iv = IV[:block_offset]
    flipped_iv += strxor( strxor(OLD_STR,NEW_STR), IV[block_offset:block_offset+len(OLD_STR)] )
    flipped_iv += IV[block_offset+len(OLD_STR):]

    print("\033[32m\n[+] Flipped IV: (%d bytes)" % len(flipped_iv))
    print("    %s" % flipped_iv.hex())
    
else:
    # If the string to flip is in a regular CBC block, flip the bits in the previous block

    # pos = same block offset, in previous block
    pos = (in_block - 1) * BLOCK_SIZE + block_offset
    end_pos = pos + len(OLD_STR)

    # here the magic happens...
    flipped_ciphertext = CIPHERTEXT[:pos]
    flipped_ciphertext += strxor( strxor(OLD_STR,NEW_STR), CIPHERTEXT[pos:end_pos] )
    flipped_ciphertext += CIPHERTEXT[end_pos:]

    print("\033[32m\n[+] Flipped ciphertext: (%d bytes)" % len(flipped_ciphertext))
    print("    %s" % flipped_ciphertext.hex())
    print("\n[+] Flipped ciphertext [BASE64]:")
    print("    " + base64.b64encode(flipped_ciphertext).decode() + "\033[0m")