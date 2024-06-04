''' 
Pseudorandom function implemented with Decisional Diffie-Hellman Assumption
https://crypto.stanford.edu/pbc/notes/crypto/prf.html
'''

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import long_to_bytes
from os import urandom 

class AES_PRF:
    '''
    Implement of a simple PRF using AES.
    '''
    def __init__(self, key: bytes = None):
        '''
        Configure the key for the PRF. 
        + key: The key to use for the PRF. If None, generate a random key.
        '''
        # print(key)
        if key is not None: 
            assert len(key) == 16

        if key is None: 
            key = self.keygen()
        self.key = key

    def keygen(self):
        '''
        Generate a random key for the PRF. 
        '''
        return urandom(16)

    def eval(self, x: int) -> bytes:
        '''
        Evaluate the PRF at x. 
        + x: The input to the PRF. 
        The output will be a 256-bit bytestream: AES(key, pad(x, 16)) || AES(key, pad(x, 16)[::-1])
        '''
        pad_message = pad(long_to_bytes(x), 16)
        cipher = AES.new(self.key, AES.MODE_ECB)
        key_1st = cipher.encrypt(pad_message)
        cipher = AES.new(self.key, AES.MODE_ECB)
        key_2nd = cipher.encrypt(pad_message[::-1])
        return key_1st + key_2nd
    