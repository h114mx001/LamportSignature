from Crypto.Hash import SHA256
from os import urandom                 

import json # for serialization

from LamportSignature.utils import *
from LamportSignature.ChaCha20_CSPRNG import ChaCha20_CSPRNG

class LamportSignature:
    def __init__(self, message: bytes = None, verify_key_0: list[bytes] = None, verify_key_1: list[bytes] = None, signature: bytes = None):
        '''
        Initialize the Lamport signature with a message, verify key pair, and signature. 
        You can either create a Null signature, or a signature with a message, verify key pair, and signature. (Does not need to be verified. We will check if we want in verify())
        + message: the message that you want to sign, in `bytes`
        + verify_key_0: 32*256 bit key for 0-bit
        + verify_key_1: 32*256 bit key for 1-bit
        + signature: the signature of the message
        '''
        if message == None and verify_key_0 == None and verify_key_1 == None and signature == None:
            return 
        
        if len(message) != BYTE_SIZE:
            raise ValueError("Invalid message length. Please provide a 256-bit message")
        if len(signature) != BIT_SIZE * BYTE_SIZE:
            raise ValueError("Invalid signature length. Please provide a valid signature")
        if not verify_key(verify_key_0) or not verify_key(verify_key_1):
            raise ValueError("Invalid verify keys. Please provide a valid verify key/re-check the generated verify key")
        
        self.message = message
        self.verify_key_0 = verify_key_0
        self.verify_key_1 = verify_key_1
        self.signature = signature

    def verify(self) -> bool: 
        '''
        Verify the signature. 
        Return True if the signature is valid, False otherwise
        '''
        signature_blocks = blockerize(self.signature, BYTE_SIZE)
        message_bit_array = get_bit_array(self.message)

        for i, m_i in enumerate(message_bit_array):
            if m_i == False:
                if SHA256.new(signature_blocks[i]).digest() != self.verify_key_0[i]:
                    return False
            else:
                if SHA256.new(signature_blocks[i]).digest() != self.verify_key_1[i]:
                    return False
        return True   

    def get_bare_signature(self) -> bytes:
        '''
        Return the signature in a bare form
        '''
        return self.signature

    def serialize(self) -> str: 
        '''
        Return the signature as a JSON string
        '''
        return json.dumps({
            "message": self.message.hex(),
            "verify_key_0": [key.hex() for key in self.verify_key_0],
            "verify_key_1": [key.hex() for key in self.verify_key_1],
            "signature": self.signature.hex()
        })
    
    def deserialize(self, serialized_signature: str):
        '''
        Unflatten the signature
        TODO: Implement some check on the signature and verify keys
        '''
        signature_dict = json.loads(serialized_signature)
        
        self.message = bytes.fromhex(signature_dict["message"])
        # assert len(self.message) == BYTE_SIZE
        self.verify_key_0 = [bytes.fromhex(key) for key in signature_dict["verify_key_0"]]

        self.verify_key_1 = [bytes.fromhex(key) for key in signature_dict["verify_key_1"]]
        self.signature = bytes.fromhex(signature_dict["signature"])
        

class Lamport_256_bit:
    '''
    Lamport signature scheme. Primitive and original for one-time signature only
    '''
    def __init__(self, sign_key_0: list[bytes] = None, sign_key_1: list[bytes] = None):
        '''
        Keygen function for Lamport signature scheme. These keys should come from a cryptographically secure random number generator, and be kept secret. If key0 and key1 are not provided, generate a new key pair.

        + sign_key_0: 32*256 bit key for 0-bit
        + sign_key_1: 32*256 bit key for 1-bit
        '''
        if sign_key_0 is None:
            sign_key_0 = [urandom(BYTE_SIZE) for _ in range(BIT_SIZE)]
        if sign_key_1 is None:
            sign_key_1 = [urandom(BYTE_SIZE) for _ in range(BIT_SIZE)]
        
        if not verify_key(sign_key_0) or not verify_key(sign_key_1):
            raise ValueError("Invalid sign keys. Please provide a valid sign key/re-check the generated sign key")
        
        self.sign_key_0 = sign_key_0
        self.sign_key_1 = sign_key_1
        self.verify_key0 = [SHA256.new(key).digest() for key in sign_key_0]
        self.verify_key1 = [SHA256.new(key).digest() for key in sign_key_1]

    def sign_256_bit_message(self, message: bytes) -> LamportSignature:
        '''
        Sign a 256-bit message.
        + message: the message that you want to sign, in `bytes`
        return: a one-time signature from the sign_key pair
        '''
        if len(message) != BYTE_SIZE:
            raise ValueError("Invalid message length. Please provide a 256-bit message")
        
        signature = b""
        message_bit_array = get_bit_array(message)
        for i, m_i in enumerate(message_bit_array):
            if m_i:
                signature += self.sign_key_1[i]
                continue 
            signature += self.sign_key_0[i]
        return LamportSignature(message, self.verify_key0, self.verify_key1, signature)

    def get_verify_key_pair(self) -> bytes:
        '''
        Return the verify key pair, as a bytes object 
        '''
        return b"".join(self.verify_key0) + b"".join(self.verify_key1)
    
class Lamport_ChaCha20(Lamport_256_bit):
    def __init__(self, secret_seed):
        '''
        Initialize the Lamport signature scheme with a secret seed
        + secret_seed: the secret seed for the ChaCha20 CSPRNG. Must be 32 bytes
        '''
        self.secret_seed = secret_seed
        self.csprng = ChaCha20_CSPRNG(secret_seed)
        sign_key_0 = [self.csprng.get_random_bytes(BYTE_SIZE) for _ in range(BIT_SIZE)]
        sign_key_1 = [self.csprng.get_random_bytes(BYTE_SIZE) for _ in range(BIT_SIZE)]
        super().__init__(sign_key_0, sign_key_1)

