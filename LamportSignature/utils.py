BIT_SIZE=256
BYTE_SIZE=BIT_SIZE//8

def verify_key(key: list[bytes]) -> bool:
    '''
    Verify the key. As Lamport signature scheme has verify key the same as sign key, this can be reused in both phase of checking.
    '''
    if len(key) != BIT_SIZE:
        return False 
    for i in range(BIT_SIZE):
        # a little bit tricky here, a 1-bit number is also 256-bit right :)
        if len(key[i]) > 32:
            return False
    return True

def blockerize(data: bytes, block_size: int) -> list[bytes]:
    '''
    Split data into blocks of block_size
    '''
    return [data[i:i+block_size] for i in range(0, len(data), block_size)]

def get_bit_array(data: bytes) -> list[bool]:
    '''
    Get the bit array of the data
    '''
    bit_array = []
    for b in data: 
        for i in range(8):
            bit_array.append((b & (1 << i)) != 0)
    return bit_array

