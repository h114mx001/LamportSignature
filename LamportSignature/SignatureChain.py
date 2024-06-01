from Crypto.Hash import SHA256
from typing_extensions import Self 
import json 

from LamportSignature.Lamport import Lamport_ChaCha20, LamportSignature
from os import urandom 

class LamportSignatureChain_Signature:
    '''
    A signature on the Lamport signature chain
    '''
    def __init__(self, state: int = None, current_state_signature: LamportSignature = None, past_state_signature: Self = None):
        '''
        Initialize a signature on the Lamport signature chain. You can either create a Null signature, or a signature with a state, current state signature, and past state signature.
        + state: the state of the signature chain
        + current_state_signature: the current state signature
        + past_state_signature: the past (latest) state signature
        '''
        if state == None and current_state_signature == None and past_state_signature == None:
            return 
        self.state = state
        self.current_state_signature = current_state_signature
        self.past_state_signature = past_state_signature

    def verify(self) -> bool: 
        '''
        Verify the signature
        Return True if the signature is valid, False otherwise
        '''
        # verify the current state signature
        if not self.current_state_signature.verify():
            return False
        # verify the past state signatures
        past_state = self.past_state_signature
        while past_state is not None:
            if not past_state.current_state_signature.verify():
                return False
            past_state = past_state.past_state_signature
        return True
    
    def serialize(self) -> str: 
        ''' 
        Serialize the signature into a JSON string
        '''
        return json.dumps({
            "state": self.state,
            "current_state_signature": self.current_state_signature.serialize(),
            "past_state_signature": self.past_state_signature.serialize() if self.past_state_signature is not None else None
        })
    
    def deserialize(self, serialized_signature: str): 
        '''
        Load the signature from the serialized version
        + serialized_signature: the serialized version of the signature
        '''
        deserialized_signature = json.loads(serialized_signature)    
        self.state = deserialized_signature["state"]
        self.current_state_signature = LamportSignature()
        self.current_state_signature.deserialize(deserialized_signature["current_state_signature"])
        if deserialized_signature["past_state_signature"] is not None:
            self.past_state_signature = LamportSignatureChain_Signature()
            self.past_state_signature.deserialize(deserialized_signature["past_state_signature"])
        else:
            self.past_state_signature = None

class LamportSignatureChain: 
    '''
    Implementation of the signer for Lamport Signature, as a stateful signature chain 
    '''
    def __init__(self, secret_seed: bytes):
        '''
        Initialize the Lamport signature chain with a secret seed
        + secret_seed: the secret seed for the Lamport signature chain, in `bytes`. Must be 32 bytes
        '''
        # generate the sk_0 and vk_0
        self.current_Lamport = Lamport_ChaCha20(secret_seed)
        # indicate the state
        self.state = 0
        self.last_signature = None 

    def sign(self, message: bytes) -> LamportSignatureChain_Signature:
        '''
        Sign a message with the Lamport signature chain. The state of the chain will be updated after signing. 
        + message: the message to sign, in `bytes`
        '''
        # generate a new Lamport pair. Seed sampled from /dev/urandom for your CSPRNG fetish :)))
        new_Lamport = Lamport_ChaCha20(urandom(32))
        # sign the message with the current Lamport pair 
        new_Lamport_verify_key = new_Lamport.get_verify_key_pair()
        # hash the message || new_Lamport_verify_key first, to assert 256-bit message
        message_hashed = SHA256.new(message + new_Lamport_verify_key).digest()
        signature = self.current_Lamport.sign_256_bit_message(message_hashed)
        # update the state and return the final signature 
        final_signature = LamportSignatureChain_Signature(self.state, signature, self.last_signature)
        self.state += 1 
        self.last_signature = final_signature
        return final_signature
    
