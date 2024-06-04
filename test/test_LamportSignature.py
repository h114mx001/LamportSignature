from LamportSignature.Lamport import LamportSignature, LamportSigningKeyPair, Lamport_ChaCha20_SHA256_keygen
from LamportSignature.SignatureChain import LamportSignatureChain_Signature, LamportSignatureChain
from LamportSignature.PRSignatureTree import LamportPRSignatureTree, LamportSignatureTree_Signature
from os import urandom
import configparser
from base64 import b64decode
from random import randint
import pytest 

cfg = configparser.RawConfigParser()
config_path = "setup.cfg"
cfg.read(config_path)
cfg_dict = dict(cfg.items("keys"))
secret_seed = b64decode(cfg_dict["secret_seed"])

def test_Lamport_Primitive():
    message = urandom(32)
    sign_key_0 = [urandom(32) for _ in range(256)]
    sign_key_1 = [urandom(32) for _ in range(256)]
    sign_key = LamportSigningKeyPair(sign_key_0, sign_key_1)
    verify_key = sign_key.get_verify_key_pairs()
    signature = sign_key.sign_primitive(message)
    assert verify_key.verify_primitive(message, signature) == True

def test_Lamport_Primitive_serialization():
    message = urandom(32)
    sign_key_0 = [urandom(32) for _ in range(256)]
    sign_key_1 = [urandom(32) for _ in range(256)]
    sign_key = LamportSigningKeyPair(sign_key_0, sign_key_1)
    verify_key = sign_key.get_verify_key_pairs()
    signature = sign_key.sign_primitive(message)
    assert verify_key.verify_primitive(message, signature) == True
    serialized = signature.serialize()
    new_signature = LamportSignature.deserialize(serialized)
    assert verify_key.verify_primitive(message, new_signature) == True

def test_Lamport_ChaCha20_SHA256_256bit_message():
    message = urandom(32)
    seed = secret_seed
    sign_key = Lamport_ChaCha20_SHA256_keygen(seed)
    verify_key = sign_key.get_verify_key_pairs()
    signature = sign_key.hash_and_sign(message)
    assert verify_key.hash_and_verify(message, signature) == True
    serialized = signature.serialize()
    new_signature = LamportSignature.deserialize(serialized)
    assert verify_key.hash_and_verify(message, new_signature) == True

def test_Lamport_ChaCha20_SHA256_arbitrary_length_message():
    length = randint(1, 1000)
    message = urandom(length)
    seed = secret_seed
    sign_key = Lamport_ChaCha20_SHA256_keygen(seed)
    verify_key = sign_key.get_verify_key_pairs()
    signature = sign_key.hash_and_sign(message)
    assert verify_key.hash_and_verify(message, signature) == True
    serialized = signature.serialize()
    new_signature = LamportSignature.deserialize(serialized)
    assert verify_key.hash_and_verify(message, new_signature) == True

def test_Lamport_Primitive_forty_times_256_bit_messages():
    for _ in range(40):
        message = urandom(32)
        sign_key_0 = [urandom(32) for _ in range(256)]
        sign_key_1 = [urandom(32) for _ in range(256)]
        sign_key = LamportSigningKeyPair(sign_key_0, sign_key_1)
        verify_key = sign_key.get_verify_key_pairs()
        signature = sign_key.sign_primitive(message)
        assert verify_key.verify_primitive(message, signature) == True

# @pytest.mark.skip(reason="temporarily disable for debugging")
def test_one_time_signature_chain_256_bit_messages():
    sc = LamportSignatureChain(secret_seed)
    message = urandom(32)
    signature = sc.sign(message)
    assert LamportSignatureChain.verify(1, message, signature) == True

# @pytest.mark.skip(reason="temporarily disable for debugging")
def test_five_times_signature_chain_256_bit_messages():
    sc = LamportSignatureChain(secret_seed)
    for state in range(1, 5+1): 
        message = urandom(32)
        signature = sc.sign(message)
        assert LamportSignatureChain.verify(state, message, signature) == True

# @pytest.mark.skip(reason="temporarily disable for debugging")
def test_forty_times_signature_chain_arbitrary_length_messages():
    sc = LamportSignatureChain(secret_seed)
    for state in range(1, 40+1): 
        message = urandom(randint(1, 1000))
        signature = sc.sign(message)
        assert LamportSignatureChain.verify(state, message, signature) == True

# @pytest.mark.skip(reason="temporarily disable for debugging")
def test_five_times_serialize_deserialize_signature_chain():
    sc = LamportSignatureChain(secret_seed)
    for state in range(1, 5+1):
        message = urandom(randint(1, 1000))
        signature = sc.sign(message)
        assert LamportSignatureChain.verify(state, message, signature) == True
        serialized = signature.serialize()
        new_signature = LamportSignatureChain_Signature.deserialize(serialized)
        assert LamportSignatureChain.verify(state, message, new_signature) == True


def test_one_time_signature_tree(): 
    key = urandom(16)
    L = 3 
    signature_tree = LamportPRSignatureTree(L, key)
    message = urandom(32)
    signature = signature_tree.sign(message)
    result = signature_tree.verify(0, message, signature)
    assert result == True

def test_one_time_signature_tree_serialization():
    key = urandom(16)
    L = 3 
    signature_tree = LamportPRSignatureTree(L, key)
    message = urandom(32)
    signature = signature_tree.sign(message)
    result = signature_tree.verify(0, message, signature)
    assert result == True
    serialized = signature.serialize()
    new_signature = LamportSignatureTree_Signature.deserialize(serialized)
    result = signature_tree.verify(0, message, new_signature)
    assert result == True

def test_five_time_signature_tree_serialization():
    key = urandom(16)
    L = 3 
    signature_tree = LamportPRSignatureTree(L, key)
    for i in range(0, 5):
        message = urandom(32)
        signature = signature_tree.sign(message)
        result = signature_tree.verify(i, message, signature)
        assert result == True
        serialized = signature.serialize()
        new_signature = LamportSignatureTree_Signature.deserialize(serialized)
        result = signature_tree.verify(i, message, new_signature)
        assert result == True

def test_forty_time_signature_tree_serialization():
    key = urandom(16)
    L = 6
    signature_tree = LamportPRSignatureTree(L, key)
    for i in range(0, 40):
        message = urandom(32)
        signature = signature_tree.sign(message)
        result = signature_tree.verify(i, message, signature)
        assert result == True
        serialized = signature.serialize()
        new_signature = LamportSignatureTree_Signature.deserialize(serialized)
        result = signature_tree.verify(i, message, new_signature)
        assert result == True

def test_overload_sign_tree():
    key = urandom(16)
    L = 1
    signature_tree = LamportPRSignatureTree(L, key)
    with pytest.raises(Exception):
        for i in range(100):
            message = urandom(32)
            signature = signature_tree.sign(message)
            result = signature_tree.verify(i, message, signature)
    
