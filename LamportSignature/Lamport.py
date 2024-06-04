from __future__ import annotations
from Crypto.Hash import SHA256
from os import urandom                 

import json # for serialization

from LamportSignature.utils import *
from LamportSignature.ChaCha20_CSPRNG import ChaCha20_CSPRNG

class LamportVerifyKeyPair: 
    '''
    Define the signing key pair for the Lamport signature scheme 
    '''
    def __init__(self, verify_key_0: list[bytes], verify_key_1: list[bytes]):
        '''
        Initialize the signing key pair with the verify key pair
        + verify_key_0: 32*256 bit key for 0-bit
        + verify_key_1: 32*256 bit key for 1-bit
        '''
        if not verify_key(verify_key_0) or not verify_key(verify_key_1):
            raise ValueError("Invalid verify keys. Please provide a valid verify key/re-check the generated verify key")
        
        self._verify_key_0 = verify_key_0
        self._verify_key_1 = verify_key_1

    def __verify(self, message: bytes, signature: LamportSignature) -> bool: 
        '''
        Verify the signature. Primitive way. Do not use this directly unless you know what you are doing
        '''
        if len(message) != BYTE_SIZE:
            raise ValueError("Invalid message length. Please provide a 256-bit message")
        if len(signature.signature) != BIT_SIZE * BYTE_SIZE:
            raise ValueError("Invalid signature length. Please provide a valid signature")
        
        message_bit_array = get_bit_array(message)
        signature_blocks = blockerize(signature.signature, BYTE_SIZE)
        for i, m_i in enumerate(message_bit_array):
            if m_i:
                if SHA256.new(signature_blocks[i]).digest() != self._verify_key_1[i]:
                    return False
                continue
            if SHA256.new(signature_blocks[i]).digest() != self._verify_key_0[i]:
                return False
        return True
    
    def verify_primitive(self, message: bytes, signature: LamportSignature) -> bool:
        '''
        Verify the signature. Primitive way. Use for task #1 testing
        '''
        return self.__verify(message, signature)
    
    def hash_and_verify(self, message: bytes, signature: LamportSignature) -> bool:
        '''
        Hash-and-verify the signature. 
        '''
        hashed_message = SHA256.new(message).digest()
        if hashed_message != signature.message:
            return False
        return self.__verify(hashed_message, signature)
    

    def get_verify_key_pair_as_tuple(self) -> tuple:
        '''
        Get the verify key pairs as a tuple
        '''
        return (self._verify_key_0, self._verify_key_1)
    
    def get_verify_key_pair_as_bytes(self) -> bytes: 
        '''
        Get the verify key pair as a bytestream
        '''
        return b"".join(self._verify_key_0 + self._verify_key_1)

    def serialize(self) -> str: 
        '''
        Serialize the verify key pair
        '''
        return json.dumps({
            "verify_key_0": [key.hex() for key in self._verify_key_0],
            "verify_key_1": [key.hex() for key in self._verify_key_1]
        })
    
    @staticmethod
    def deserialize(serialized_verify_key: str):
        '''
        Deserialize the verify key pair
        '''
        verify_key_dict = json.loads(serialized_verify_key)
        verify_key_0 = [bytes.fromhex(key) for key in verify_key_dict["verify_key_0"]]
        verify_key_1 = [bytes.fromhex(key) for key in verify_key_dict["verify_key_1"]]
        return LamportVerifyKeyPair(verify_key_0, verify_key_1)

class LamportSignature:
    '''
    Define the bare-borned Lamport Signature. Should not be used directly unless you know what you are doing
    '''
    def __init__(self, message: bytes = None, signature: bytes = None):
        self.message = message
        self.signature = signature

    def serialize(self) -> str: 
        '''
        Serialize the signature
        '''
        return json.dumps({
            "message": self.message.hex(),
            "signature": self.signature.hex()
        })

    @staticmethod
    def deserialize(serialized_signature: str):
        '''
        Deserialize the signature
        '''
        signature_dict = json.loads(serialized_signature)
        
        message = bytes.fromhex(signature_dict["message"])
        signature = bytes.fromhex(signature_dict["signature"])
        return LamportSignature(message, signature)

class LamportSigningKeyPair: 
    ''' 
    Define the signing key pair for the Lamport signature scheme 
    '''

    def __init__(self, sign_key_0: list[bytes], sign_key_1: list[bytes]):
        '''
        Initialize the signing key pair with the sign key pair
        + sign_key_0: 32*256 bit key for 0-bit
        + sign_key_1: 32*256 bit key for 1-bit
        '''
        if not verify_key(sign_key_0) or not verify_key(sign_key_1):
            raise ValueError("Invalid sign keys. Please provide a valid sign key/re-check the generated sign key")
        
        self._sign_key_0 = sign_key_0
        self._sign_key_1 = sign_key_1
        self._verify_key0 = [SHA256.new(key).digest() for key in sign_key_0]
        self._verify_key1 = [SHA256.new(key).digest() for key in sign_key_1]
    
    def get_verify_key_pairs(self) -> LamportVerifyKeyPair:
        '''
        Get the corresponding verify key pair for the signing key
        '''
        return LamportVerifyKeyPair(self._verify_key0, self._verify_key1)
    
    def sign_primitive(self, message: bytes) -> LamportSignature:
        '''
        Sign the message, for the task #1 testing
        '''
        return self.__sign(message)

    def __sign(self, message: bytes) -> LamportSignature:
        '''
        Sign the message
        '''
        if len(message) != BYTE_SIZE:
            raise ValueError("Invalid message length. Please provide a 256-bit message")
        
        signature = b""
        message_bit_array = get_bit_array(message)
        for i, m_i in enumerate(message_bit_array):
            if m_i:
                signature += self._sign_key_1[i]
                continue 
            signature += self._sign_key_0[i]
        return LamportSignature(message, signature)

    def hash_and_sign(self, message: bytes) -> LamportSignature:
        '''
        Hash-and-sign the message
        '''
        return self.__sign(SHA256.new(message).digest())
    
def Lamport_ChaCha20_SHA256_keygen(secret_seed: bytes) -> LamportSigningKeyPair:
    '''
    Generate the Lamport signing key pair with the secret seed
    '''
    csprng = ChaCha20_CSPRNG(secret_seed)
    sign_key_0 = [csprng.get_random_bytes(BYTE_SIZE) for _ in range(BIT_SIZE)]
    sign_key_1 = [csprng.get_random_bytes(BYTE_SIZE) for _ in range(BIT_SIZE)]
    return LamportSigningKeyPair(sign_key_0, sign_key_1)