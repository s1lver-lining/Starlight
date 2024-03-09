from md5 import MD5

def extend_hash(current_hash:str, unknown_size:int, appended_data:bytes) -> str:
    """
    If current_hash = MD5(unknown) where unknown is unknown_size bytes long, then
    we can compute MD5(pad(unknown) + append) without knowing unknown.
    
    Args:
        current_hash (str): the current hash in hexadecimal
        unknown_size (int): the size of the unknown message
        appended_data (bytes): the data to append to the unknown message

    Returns:
        str: the hash of (unknown + append)
    """

    # Load the state from the current hash
    md5 = MD5()
    md5.load_state_from_hash(current_hash)

    # Compute the number of 64-byte blocks that have already been hashed
    dummy_unknown = b'A' * unknown_size
    padded_dummy_unknown = MD5.pad(dummy_unknown)
    prev_blocs_count = len(padded_dummy_unknown) // 64

    # Add the append data to the message
    padded_append = MD5.pad(appended_data, prev_blocs_count)
    for i in range(0, len(padded_append), 64):
        md5.compress(padded_append[i:i + 64])

    # Return the hash of the extended message
    return md5.digest().hex()
    