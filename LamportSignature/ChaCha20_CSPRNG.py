'''
Implementation of ChaCha20 as a CSPRNG
'''

from Crypto.Cipher import ChaCha20

class ChaCha20_CSPRNG:
    def __init__(self, seed):
        self.seed = seed
        self.cipher = ChaCha20.new(key=seed, nonce=b'\x00'*8)
        self.counter = 0
    
    def get_random_bytes(self, num_bytes):
        '''
        Get random bytes from the CSPRNG
        '''
        random_bytes = b""
        while len(random_bytes) < num_bytes:
            random_bytes += self.cipher.encrypt(self.counter.to_bytes(8, byteorder='little'))
            self.counter += 1
        return random_bytes[:num_bytes]
    