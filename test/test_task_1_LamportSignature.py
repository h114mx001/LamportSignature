from LamportSignature.Lamport import LamportSignature, LamportSigningKeyPair, Lamport_ChaCha20_SHA256_keygen
from test import secret_seed
from os import urandom
from random import randint
import pytest 

# from LamportSignature.PRSignatureTree import LamportPRSignatureTree, LamportSignatureTree_Signature, LamportDeterministicSignatureTree

@pytest.mark.task1
def test_Lamport_Primitive():
    message = urandom(32)
    sign_key_0 = [urandom(32) for _ in range(256)]
    sign_key_1 = [urandom(32) for _ in range(256)]
    sign_key = LamportSigningKeyPair(sign_key_0, sign_key_1)
    verify_key = sign_key.get_verify_key_pairs()
    signature = sign_key.sign_primitive(message)
    assert verify_key.verify_primitive(message, signature) == True

@pytest.mark.task1
def test_Lamport_malformed_signature():
    message = urandom(32)
    sign_key_0 = [urandom(32) for _ in range(256)]
    sign_key_1 = [urandom(32) for _ in range(256)]
    sign_key = LamportSigningKeyPair(sign_key_0, sign_key_1)
    verify_key = sign_key.get_verify_key_pairs()
    signature = sign_key.sign_primitive(message)
    # signature will be flipped a random bit 
    rand_bit = randint(0, 32 * 256 - 1)
    signature.signature = signature.signature[:rand_bit] + bytes([signature.signature[rand_bit] ^ 1]) + signature.signature[rand_bit + 1:]
    assert verify_key.verify_primitive(message, signature) == False

@pytest.mark.task1
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

@pytest.mark.task1
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

@pytest.mark.task1
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

@pytest.mark.task1
def test_Lamport_Primitive_forty_times_256_bit_messages():
    for _ in range(40):
        message = urandom(32)
        sign_key_0 = [urandom(32) for _ in range(256)]
        sign_key_1 = [urandom(32) for _ in range(256)]
        sign_key = LamportSigningKeyPair(sign_key_0, sign_key_1)
        verify_key = sign_key.get_verify_key_pairs()
        signature = sign_key.sign_primitive(message)
        assert verify_key.verify_primitive(message, signature) == True
