# Lamport Signature Scheme 

Cryptography - COMP4050 - Final Project 

## Description 

This is the Python Implementation of the Lamport Signature Scheme, a post-quantum cryptographic & secret-key signature scheme. 

This implementation includes: 

+ Primitive Lamport Signature Scheme (Currently hard-coded for handling 256-bit messages, with SHA-256 as the hash function). 
  + Come up with a home-made serialization/deserialization for the signature, using `json` module.
+ Lamport-ChaCha20-Merkle for using 256-bit secret as seed for generate the private key, from a ChaCha20, as well as Merkle Tree for compressing the verify key.
  + Come up with a home-made serialization/deserialization for the private key, using `json` module.
+ ... TBD

## Installation

```bash
git clone ... 
virtualenv .venv
source .venv/bin/activate
pip install -r requirements.txt
``` 

## Testing 

```bash
pytest -v
```

For coverage, run: 

```bash
pytest -v --cov
```

## Disclaimer

1. This whole package is just a proof of concept and should not be used in production. 
2. Using ChaCha20 as a CSPRNG is not recommended for production. TL;DR: Because lots of requirement for Key Erasure and protection, high-level language with garbage collector is not recommended for this kind of task. [Read More](https://www.bentasker.co.uk/posts/blog/software-development/689-writing-a-chacha20-based-csprng.html). I am only use this because of the requirement for a setting of seed. Actually, for the CSPRNG, uses `os.urandom()` could be the easiest approach.
3. This implementation does not take into account some acceleration/optimization, but only the bare-bone implementation. Performance is still a big issue, FYI.