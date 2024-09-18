# Lamport Signature Scheme 

This is the Python Implementation of the Lamport Signature Scheme, a post-quantum cryptographic & secret-key signature scheme. 

This implementation includes: 

- [x] (Task 01) Primitive Lamport Signature Scheme (Currently hard-coded for handling 256-bit messages, with SHA-256 as the hash function). 
- [x] (Task 01) A keygen function that takes advantage of `ChaCha20` as a CSPRNG for generating the private key.
- [x] (Ultility) Hash-and-sign mode for the message, which uses the hash of the message as the message itself. The default hash function is `SHA-256`.
- [x] (Task 02) Implementation of Signature Chain, which is used for achieve Many-Time Signature (MTS) from the Lamport Signature Scheme.
- [x] (Task 03) Implementation of Lamport Signature Pseudorandom Tree, which is used for achieve Many-Time Signature (OTS) from the Lamport Signature Scheme. The PRF for the node to be used is based on a home-made implementation from AES-128-ECB (indeedly, not provenly secure :D)
- [x] (Task 04) Implementation of Lamport Signature Deterministic Tree, which inherited the Pseudorandom Tree, but with a deterministic counter that can determine which leaf node to be used for signing. 

For more information about each modules, please refer to the [README file](./LamportSignature/README.md) inside the package

## Installation

```bash
git clone ... 
virtualenv .venv
source .venv/bin/activate
pip install -r requirements.txt
``` 

## Testing 

Firstly, you need to generate the seed for the ChaCha20 CSPRNG. You can do this by running the following command: 

```bash
python keygen.py
```

This will create a `setup.cfg` file that has the seed, in base64 format. 

Then, you can run the test by running:

```bash
pytest -v
```

For coverage, run: 

```bash
pytest -v --cov
```

### For grading us (To COMP4050 Instructors :D)

There are 04 tags that we have setup in `pyproject.toml`, to simplify your grading. The tags are: `task1`, `task2`, `task3`, and `task4`.

To test the code for each task, you can run the following command: 

```bash
pytest -v -m task1
```
Please replace `task1` with `task2`, `task3`, or `task4` for the corresponding task.

## Some... a little bit cool stuff that differs from the requirements

1. We implemented the signature schemes in an OOP style, which makes the code more readable, maintainable, and extensible. Also, we implemented serialization and deserialization for common load/store objects like the Signature, the Verify Key pair, etc. This helps us a lot in debugging and testing.
2. We implemented the `Hash-and-Sign` mode, which is a common practice in the real world. This mode uses the hash of the message as the message itself, which helps to reduce the size of the message and also makes the signature more secure.
3. The implementation of signature tree has some tweaks, such as an internal cache of leaf nodes & authentication paths, which helps to reduce the time complexity of the signing process, with some trade-offs in memory usage (not much, though).
4. We implemented our own PRF functions to derived the next node for the Deterministic Tree, where the PRF is based on AES_128_ECB, and SHA-256. This function prevents the chance of collision in determining the next node, which is a potential denial-of-service for the deterministic tree. 

## Disclaimer

1. This whole package is just a proof of concept and should not be used in production. 
2. Using ChaCha20 as a CSPRNG is not recommended for production. TL;DR: Because lots of requirement for Key Erasure and protection, high-level language with garbage collector is not recommended for this kind of task. [Read More](https://www.bentasker.co.uk/posts/blog/software-development/689-writing-a-chacha20-based-csprng.html). I am only use this because of the requirement for a setting of seed. Actually, for the CSPRNG, uses `os.urandom()` could be the easiest approach.
3. Many cryptographic functions in this packages are not provenly secure, as we have mentioned above. It is an additional thing that you should never use this in production.
4. This implementation does not take into account some acceleration/optimization, but only the bare-bone implementation. Performance is still a big issue, FYI.
