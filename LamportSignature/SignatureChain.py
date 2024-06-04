from LamportSignature.Lamport import *

from os import urandom 
import json 

class LamportSignatureChain_Signature:
    '''
    Implementation of a signature on the Lamport signature chain
    '''
    def __init__(self, state: int = 0, past_signatures: list[LamportSignature] = None, past_verify_keys: list[LamportVerifyKeyPair] = None):
        '''
        Initialize the signature on the Lamport signature chain
        + current_signature: the current signature
        + current_verify_key: the current verify key for the current signature
        + past_signature: the past signature
        + past_verify_keys: the past verify keys
        '''
        # initialize the signature if the past signature is not provided
        self.state = state       
        self.past_signatures = past_signatures
        self.past_verify_keys = past_verify_keys

    def insert_new_signature(self, new_signature: LamportSignature, next_verify_key: LamportVerifyKeyPair):
        '''
        Insert a new signature to the signature chain
        + new_signature: the new signature
        + new_verify_key: the new verify key
        '''
        self.past_signatures.append(new_signature)
        self.past_verify_keys.append(next_verify_key)
        self.state += 1
   
    def serialize(self) -> str:
        '''
        Serialize the signature
        '''
        return json.dumps({
            "state": self.state,
            "past_signatures": [signature.serialize() for signature in self.past_signatures],
            "past_verify_keys": [verify_key.serialize() for verify_key in self.past_verify_keys]
        })
    
    @staticmethod
    def deserialize(serialized_signature: str): 
        '''
        Deserialize the signature
        '''
        signature_dict = json.loads(serialized_signature)
        state = signature_dict["state"]
        past_signatures = [LamportSignature.deserialize(signature) for signature in signature_dict["past_signatures"]]
        past_verify_keys = [LamportVerifyKeyPair.deserialize(verify_key) for verify_key in signature_dict["past_verify_keys"]]
        return LamportSignatureChain_Signature(state, past_signatures, past_verify_keys)
    
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
        self.current_Lamport = Lamport_ChaCha20_SHA256_keygen(secret_seed)
        self.current_verify_key = self.current_Lamport.get_verify_key_pairs()
        # indicate the state
        self.state = 0
        self.last_signature = LamportSignatureChain_Signature(0, [], [self.current_verify_key]) 

    def sign(self, message: bytes) -> LamportSignatureChain_Signature: 
        '''
        Sign a message with the Lamport signature chain. The state of the chain will be updated after signing. 
        + message: the message to sign, in `bytes`
        '''
        # generate a new Lamport pair. Seed sampled from /dev/urandom for your CSPRNG fetish :)))
        new_Lamport = Lamport_ChaCha20_SHA256_keygen(urandom(32))
        # sign the message with the current Lamport pair 
        new_Lamport_verify_key = new_Lamport.get_verify_key_pairs().get_verify_key_pair_as_byte()
        # hash the message || new_Lamport_verify_key first, to assert 256-bit message
        current_message = message + new_Lamport_verify_key
        current_signature = self.current_Lamport.hash_and_sign(current_message)
        # update the state and return the final signature
        self.last_signature.insert_new_signature(current_signature, new_Lamport.get_verify_key_pairs())
        self.current_Lamport = new_Lamport
        self.current_verify_key = self.current_Lamport.get_verify_key_pairs()
        self.state += 1
        return self.last_signature
    
    @staticmethod
    def verify(state: int, message: bytes, signature: LamportSignatureChain_Signature) -> bool:
        '''
        Verify the signature
        + state: the state of the signature chain
        + message: the message to verify, in `bytes`
        + signature: the signature to verify
        Return True if the signature is valid, False otherwise
        '''
        # verify the current state signature
        # print(signature.past_signatures)
        state_signature = signature.past_signatures[state-1]
        state_verify_key_pair = signature.past_verify_keys[state-1]
        state_appended_verify_key_bytes = signature.past_verify_keys[state].get_verify_key_pair_as_byte()
        # print(state_signature.message.hex())        
        padded_message = message + state_appended_verify_key_bytes
        # print(SHA256.new(padded_message).hexdigest())
        if not state_verify_key_pair.hash_and_verify(padded_message, state_signature):
            return False
        print("verified the current signature")
        # verify the past signatures
        for i in range(0, state - 1):
            signature_i = signature.past_signatures[i]
            verify_key_i_1 = signature.past_verify_keys[i]
            print(signature_i.message.hex())
            if not verify_key_i_1.verify_primitive(signature_i.message, signature_i):
                print(f"Failed at {i}")
                return False
        return True
