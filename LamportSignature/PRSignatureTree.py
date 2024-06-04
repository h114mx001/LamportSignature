from LamportSignature.Lamport import LamportSignature, LamportSigningKeyPair, LamportVerifyKeyPair, Lamport_ChaCha20_SHA256_keygen   
from LamportSignature.AES_PRF import AES_PRF

import json

class LamportSignatureTree_Signature:
    '''
    Define the signature layout for the Lamport signature tree
    '''
    def __init__(self, counter, authentication_path: list[bytes], message: bytes, signature: bytes):
        '''
        Initialize the signature with the authentication path, message, and signature
        + authentication_path: The authentication path for the signature
        + message: The message that is signed
        + signature: The signature
        '''
        self.counter = counter
        self.authentication_path = authentication_path
        self.message = message
        self.signature = signature

    def serialize(self):
        '''
        Serialize the signature
        '''
        return json.dumps({
            "counter": self.counter,
            "authentication_path": [auth_path.hex() for auth_path in self.authentication_path],
            "message": self.message.hex(),
            "signature": self.signature.hex()
        })
    
    @staticmethod
    def deserialize(serialized: str):
        '''
        Deserialize the signature
        '''
        data = json.loads(serialized)
        return LamportSignatureTree_Signature(
            data["counter"],
            [bytes.fromhex(auth_path) for auth_path in data["authentication_path"]],
            bytes.fromhex(data["message"]),
            bytes.fromhex(data["signature"])
        )

class LamportPRSignatureTree_Node:
    '''
    Design of the signature tree, in order to verify as a binary tree.
    ''' 
    def __init__(self, id: int, prf: AES_PRF):
        '''
        Initialize the node with an id and a PRF, in security level L
        '''
        # Lamport's specific attributes
        self.id = id 
        self.prf = prf 
        
        # Binary tree's specific attributes
        self.is_root = False 
        if self.id == 0:
            self.is_root = True
        self.left = None
        self.right = None
        self.parent = None

        # check if the node has signed something...
        self.signed = False
        # signature caching, for the authentication path
        self.signature = None

        key = self.prf.eval(self.id)
        lamport = Lamport_ChaCha20_SHA256_keygen(key)
        self.verify_key = lamport.get_verify_key_pair()
        # don't want to store the whole lamport object, just the verify key pair
        del lamport 

    def is_leaf_node(self):
        '''
        Check if this node is a leaf node
        '''
        return (self.left == None and self.right == None)
    
    def sign(self, message: bytes):
        '''
        Sign a message for the node
        + message: The message to sign
        '''
        # if the node is not the leaf node, the signature is actually for authentication path. we can cache it to avoid recomputation.
        # else, if the leaf node reuse the sign key, raise error

        if self.signed:
            if (not self.is_leaf_node()):
                return self.signature
            raise Exception("No reuse leaf's sign key for different message!")
        
        key = self.prf.eval(self.id)
        lamport = Lamport_ChaCha20_SHA256_keygen(key)
        signature = lamport.sign(message)
        self.signed = True
        self.signature = signature
        return signature
    
    def get_verify_key_pair_as_bytes(self) -> bytes: 
        '''
        Get the verify key pair as bytes
        '''
        return b"".join(self.verify_key_0 + self.verify_key_1)
        
    def verify(self, message: bytes, signature: LamportSignature): 
        '''
        Verify a message by the node's verify key pair
        + message: The message to verify
        + signature: The signature to verify
        '''
        return Lamport_ChaCha20_SHA256_Signature(message, self.verify_key_0, self.verify_key_1, signature).verify()

    def get_authentication_path_signature(self):
        '''
        Return the signature of the children's node for the authentication path.
        '''
        # if the node is a leaf node, return None 
        if self.is_leaf_node():
            return None
        left_node_verify_keys = self.left.get_verify_key_pair_as_bytes()
        right_node_verify_keys = self.right.get_verify_key_pair_as_bytes()
        # Only need to have the signature, but not the whole object. we can regen them in verification step later on
        return self.sign(left_node_verify_keys + right_node_verify_keys).signature

class LamportPRSignatureTree:
    '''
    Design of a SignatureTree, with prescribed security level L 
    '''
    def __init__(self, L: int, key: bytes = None):
        '''
        Initialize the tree with a security level L (L is the depth of the tree, do not count the root node)
        '''
        self.L = L 
        self.prf = AES_PRF(key=key)
        # counter to count which leaf node to use for signing
        self.counter = 0
        # starting leaf has same value with the 1st counter.
        self.offset = 2**self.L - 1
        self.leaves = [None for _ in range(2**self.L)]
        self.capacity = 2**self.L - 1
        self.__build_tree(L=self.L)
        

    def __str__(self):
        '''
        String representation, mostly for debug
        '''
        return f"Signature Tree with L = {self.L}, current counter = {self.counter}, capacity = {self.capacity}"
    
    def __build_tree(self, root: LamportPRSignatureTree_Node = None, L: int = None):
        '''
        Build the tree with L levels. 
        '''

        if L == 0:
            self.leaves[root.id - self.offset] = root
            return
        if root is None:
            self.root = LamportPRSignatureTree_Node(0, self.prf)
            self.__build_tree(self.root, L)
        else:
            root.left = LamportPRSignatureTree_Node(root.id * 2 + 1, self.prf)
            root.right = LamportPRSignatureTree_Node(root.id * 2 + 2, self.prf)
            root.left.parent = root
            root.right.parent = root
            self.__build_tree(root.left, L - 1)
            self.__build_tree(root.right, L - 1)
     
    def __get_node_with_id(self, id: int, starting_node: LamportPRSignatureTree_Node = None):
        '''
        Get the node with a specific id
        '''
        if starting_node is None:
            starting_node = self.root
        if starting_node.id == id:
            return starting_node
        if starting_node.is_leaf_node():
            return None
        left_node = self.__get_node_with_id(id, starting_node.left)
        if left_node is not None:
            return left_node
        right_node = self.__get_node_with_id(id, starting_node.right)
        return right_node
    
    def __get_leaf_with_id(self, counter: int) -> LamportPRSignatureTree_Node: 
        '''
        Get the leaf node with a specific counter
        '''
        return self.leaves[counter]
    
    def __get_authentication_path(self, counter: int):
        '''
        Get the authentication path for a node with a specific id
        '''
        node = self.__get_leaf_with_id(counter)
        authentication_path = []
        while node is not None:
            authentication_path.append(node.get_authentication_path_signature())
            node = node.parent
        return authentication_path[:0:-1]
    
    def sign(self, message: bytes):
        '''
        Sign a message on the signature tree
        '''
        if self.counter > self.capacity:
            raise Exception("Signature tree is full")
        # get the current node to sign
        node = self.__get_leaf_with_id(self.counter)
        authentication_path = self.__get_authentication_path(self.counter)
        signature = node.sign(message)
        # again, we don't want to store the whole lamport object, just the signature, as everything has been generated.
        signature = LamportSignatureTree_Signature(self.counter, authentication_path, signature.message, signature.signature)
        self.counter += 1
        return signature
    
    def verify(self, signature: LamportSignatureTree_Signature):
        '''
        Verify a signature
        '''
        node = self.__get_leaf_with_id(signature.counter)
        if not node.verify(signature.message, signature.signature):
            return False
        for i, auth_sig in enumerate(signature.authentication_path):
            if not node.verify(auth_sig, signature.authentication_path[i]):
                return False
            node = node.parent
        return True 