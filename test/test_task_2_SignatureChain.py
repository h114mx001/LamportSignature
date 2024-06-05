from LamportSignature.SignatureChain import LamportSignatureChain_Signature, LamportSignatureChain
from test import secret_seed

from os import urandom
from random import randint
import pytest 



# @pytest.mark.skip(reason="temporarily disable for debugging")
@pytest.mark.task2
def test_one_time_signature_chain_256_bit_messages():
    sc = LamportSignatureChain(secret_seed)
    message = urandom(32)
    signature = sc.sign(message)
    assert LamportSignatureChain.verify(1, message, signature) == True

# @pytest.mark.skip(reason="temporarily disable for debugging")
@pytest.mark.task2
def test_five_times_signature_chain_256_bit_messages():
    sc = LamportSignatureChain(secret_seed)
    for state in range(1, 5+1): 
        message = urandom(32)
        signature = sc.sign(message)
        assert LamportSignatureChain.verify(state, message, signature) == True

# @pytest.mark.skip(reason="temporarily disable for debugging")
@pytest.mark.task2
def test_forty_times_signature_chain_arbitrary_length_messages():
    sc = LamportSignatureChain(secret_seed)
    for state in range(1, 40+1): 
        message = urandom(randint(1, 1000))
        signature = sc.sign(message)
        assert LamportSignatureChain.verify(state, message, signature) == True

# @pytest.mark.skip(reason="temporarily disable for debugging")
@pytest.mark.task2
def test_five_times_serialize_deserialize_signature_chain():
    sc = LamportSignatureChain(secret_seed)
    for state in range(1, 5+1):
        message = urandom(randint(1, 1000))
        signature = sc.sign(message)
        assert LamportSignatureChain.verify(state, message, signature) == True
        serialized = signature.serialize()
        new_signature = LamportSignatureChain_Signature.deserialize(serialized)
        assert LamportSignatureChain.verify(state, message, new_signature) == True
