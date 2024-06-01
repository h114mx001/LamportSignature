from LamportSignature.Lamport import Lamport_256_bit, Lamport_ChaCha20, LamportSignature
from LamportSignature.SignatureChain import LamportSignatureChain_Signature, LamportSignatureChain
from os import urandom
import configparser
from base64 import b64decode
from random import randrange 

cfg = configparser.RawConfigParser()
config_path = "setup.cfg"
cfg.read(config_path)
cfg_dict = dict(cfg.items("keys"))
secret_seed = b64decode(cfg_dict["secret_seed"])

def test_Lamport_Primitive():
    message = urandom(32)
    sign_key_0 = [urandom(32) for _ in range(256)]
    sign_key_1 = [urandom(32) for _ in range(256)]
    l = Lamport_256_bit(sign_key_0, sign_key_1)
    signature = l.sign_256_bit_message(message)
    assert signature.verify() == True

def test_one_time_256_bit_message():
    message = urandom(32)
    l = Lamport_ChaCha20(secret_seed)
    signature = l.sign_256_bit_message(message)
    assert signature.verify() == True

def test_serialize_deserialize_Lamport():
    message = urandom(32)
    sign_key_0 = [urandom(32) for _ in range(256)]
    sign_key_1 = [urandom(32) for _ in range(256)]
    l = Lamport_256_bit(sign_key_0, sign_key_1)
    signature = l.sign_256_bit_message(message)
    serialized = signature.serialize()
    new_signature = LamportSignature()
    new_signature.deserialize(serialized)
    assert new_signature.verify() == True

def test_serialize_deserialize_LamportChaCha20():
    message = urandom(32)
    l = Lamport_ChaCha20(secret_seed)
    signature = l.sign_256_bit_message(message)
    serialized = signature.serialize()
    new_signature = LamportSignature()
    new_signature.deserialize(serialized)
    assert new_signature.verify() == True

def test_one_time_signature_chain_256_bit_messages():
    sc = LamportSignatureChain(secret_seed)
    message = urandom(32)
    signature = sc.sign(message)
    assert signature.verify() == True

def test_five_times_signature_chain_256_bit_messages():
    sc = LamportSignatureChain(secret_seed)
    for _ in range(5): 
        message = urandom(32)
        signature = sc.sign(message)
        assert signature.verify() == True

def test_forty_times_signature_chain_arbitrary_length_messages():
    sc = LamportSignatureChain(secret_seed)
    for _ in range(40): 
        message = urandom(randrange(1, 1000))
        signature = sc.sign(message)
        assert signature.verify() == True

def test_one_time_serialize_deserialize_signature_chain():
    sc = LamportSignatureChain(secret_seed)
    message = urandom(32)
    signature = sc.sign(message)
    serialized = signature.serialize()
    new_signature = LamportSignatureChain_Signature()
    new_signature.deserialize(serialized)
    assert new_signature.verify() == True

def test_five_times_serialize_deserialize_signature_chain():
    sc = LamportSignatureChain(secret_seed)
    for _ in range(5):
        message = urandom(randrange(1, 1000))
        signature = sc.sign(message)
        assert signature.verify() == True 
        serialized_signature = signature.serialize()
        new_signature = LamportSignatureChain_Signature()
        new_signature.deserialize(serialized_signature)
        assert new_signature.verify() == True