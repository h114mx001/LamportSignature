from abc import ABC, abstractmethod
from LamportSignature.AES_PRF import AES_PRF
from Crypto.Hash import SHA256
from Crypto.Util.number import bytes_to_long
from os import urandom 

class Counter: 
    '''
    Define bare-born counter module for calculating the next leaf_node to use
    '''
    @abstractmethod
    def __init__(self, state: int = 0, capacity: int = 0):
        '''
        Initialize the counter with a state and a capacity
        '''
        self.state = state
        self.capacity = capacity
        self.allocated = [False for _ in range(capacity + 1)]
        pass

    @abstractmethod
    def next(self, **kwargs) -> int:
        '''
        Calculate the next state of the counter
        '''
        pass

# This counter is for task #3
class IncreasementCounter(Counter): 
    '''
    Define the counter that increases by 1. The counter has a starting state, and a capacity
    '''
    def next(self, **kwargs) -> int:
        '''
        Calculate the next state of the counter
        '''
        if self.state > self.capacity:
            return -1
        state = self.state
        self.allocated[state] = True
        self.state += 1
        return state

# This counter is for task #4
class DeterministicCounter(Counter):
    '''
    Deterministic counter that uses AES_PRF module as the internal PRF to determine the next state
    '''
    def __init__(self, key: bytes, state: int = 0, capacity: int = 0):
        '''
        Initialize the counter with a key, a state, and a capacity
        '''
        super().__init__(state, capacity)
        self.prf = AES_PRF(key)
        
    def __str__(self):
        '''
        String representation of the counter
        '''
        return f"Deterministic Counter with state = {self.state}, capacity = {self.capacity}"
    
    def next(self, **kwargs) -> int:
        '''
        Determine the next state of the counter based on the message. 
        
        The message is hashed first with SHA256, modulo with `(self.capacity + 1)`, XORing with current state, and then being permuted with AES_PRF, and then, again,  modulo with `(self.capacity + 1)`. If there is a collision, the state will be increased by 1, until the state is not allocated.

        This design is indeedly not proven as secure. But at least, from some point of views, it prevents denial-of-service that allows attacker to forge message that make the state faulty continuously (e.g. by sending the same message multiple times)
        '''
        message = kwargs["message"]
        # hash the message
        state = SHA256.new(message).digest()
        # taking last self.capacity bits
        state = bytes_to_long(state) % (self.capacity + 1)
        # xor with current state
        state ^= self.state
        # permute with AES_PRF
        state = bytes_to_long(self.prf.eval(state)) % (self.capacity + 1)
        # if there is a collision, find the next state that fits the condition
        while self.allocated[state]:
            state += 1
            state %= (self.capacity + 1)
        self.allocated[state] = True
        self.state = state
        return state
    
