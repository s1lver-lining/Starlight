import numpy as np

BLOCK_SIZE = 64
DIGEST_SIZE = 16

rotate_by = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
         5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
         4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
         6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

index_for_step = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 
                  1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 
                  5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2,
                  0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9]

sines = np.abs(np.sin(np.arange(64) + 1))
sine_randomness = [int(x) for x in np.floor(2 ** 32 * sines)]


def left_shift_32(x:int, offset:int) -> int:
    """
    Left shift the first 4 bytes of x by offset bits.

    Args:
        x (int): 32-bit integer
        offset (int): number of bits to shift

    Returns:
        int: 32-bit integer
    """
    return (((x & 0xffffffff) << (offset & 31)) | ((x & 0xffffffff) >> (32 - (offset & 31)))) & 0xffffffff


def not_32(x:int) -> int:
    """
    Bitwise NOT of the first 4 bytes of x.

    Args:
        x (int): 32-bit integer

    Returns:
        int: 32-bit integer
    """
    return 4294967295 - (x & 0xffffffff)



def select_mixer(i:int) -> int:
    def F1(b:int, c:int, d:int) -> int:
        return d ^ (b & (c ^ d))

    def F2(b:int, c:int, d:int) -> int:
        return c ^ (d & (b ^ c))

    def F3(b:int, c:int, d:int) -> int:
        return b ^ c ^ d

    def F4(b:int, c:int, d:int) -> int:
        return c ^ (b | not_32(d))
    
    if i < 16:
        return F1
    elif i < 32:
        return F2
    elif i < 48:
        return F3
    else:
        return F4

class MD5:
    def pad(message:bytes, prev_blocs_count:int=0) -> bytes:
        """
        Pad the message according to the MD5 padding scheme.

        Args:
            message (bytes): the message to be padded
            prev_blocs_count (int): the number of 64-byte blocks in the previous message

        Returns:
            bytes: the padded message
        """
        bit_length = ((len(message) + 64*prev_blocs_count) * 8) % (2 ** 64)
        pad = message + b'\x80'
        while len(pad) % 64 != 56:
            pad += b'\x00'
        pad += bit_length.to_bytes(length=8, byteorder='little')
        return pad 
    
    def __init__(self):
        self.state:tuple[int, int, int, int] = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)
    
    def digest(self) -> bytes:
        """
        Get the digest of the message, stored in the state.
        """
        return b''.join(x.to_bytes(length=4, byteorder='little') for x in self.state)

    def compress(self, msg_chunk:bytearray) -> None:
        """
        Compress the message chunk into the state.

        Args:
            msg_chunk (bytearray): the message chunk of 64 bytes
        """
        assert len(msg_chunk) == BLOCK_SIZE
        msg_ints = [int.from_bytes(msg_chunk[i:i + 4], byteorder='little') for i in range(0, BLOCK_SIZE, 4)]
        a, b, c, d = self.state

        for i in range(BLOCK_SIZE):
            mixer_func = select_mixer(i)
            msg_index  = index_for_step[i]
            a = (a + mixer_func(b, c, d) + msg_ints[msg_index] + sine_randomness[i]) % (2 ** 32)
            a = left_shift_32(a, rotate_by[i])
            a = (a + b) % (2 ** 32)
            a, b, c, d = d, a, b, c
        
        self.state = (
            (self.state[0] + a) % (2 ** 32),
            (self.state[1] + b) % (2 ** 32),
            (self.state[2] + c) % (2 ** 32),
            (self.state[3] + d) % (2 ** 32),
        )

    def update(self, message:bytes) -> None:
        """
        Update the MD5 object with a message.

        Args:
            message (bytes): the message to be hashed

        Returns:
            bytes: the MD5 hash of the message
        """
        padded = MD5.pad(message)
        for i in range(0, len(padded), BLOCK_SIZE):
            self.compress(padded[i:i + BLOCK_SIZE])

    def load_state_from_hash(self, hash:str) -> None:
        """
        Load the state of the MD5 object from a hash.

        Args:
            hash (str): the hash to load in hexadecimal
        """
        registers = [0, 0, 0, 0]

        for i in range(len(registers)):
            registers[i] = int.from_bytes(bytes.fromhex(hash[8 * i:8 * (i + 1)]), byteorder='little')
        self.state = tuple(registers)
