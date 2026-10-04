import json
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


COMMAND = b'{"action":"READ","path":"notes.txt"}'


def encrypt(key, iv, plaintext):
    encryptor = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def relay(ciphertext, offset, original, replacement):
    """Modify known plaintext bytes without receiving the encryption key."""
    assert len(original) == len(replacement)
    modified = bytearray(ciphertext)
    delta = bytes(a ^ b for a, b in zip(original, replacement))

    for i, difference in enumerate(delta):
        modified[offset + i] ^= difference

    print("Original bytes:   ", original.hex())
    print("Replacement bytes:", replacement.hex())
    print("XOR difference:   ", delta.hex())
    return bytes(modified)


class Receiver:
    def __init__(self, key):
        self.key = key
        self.processed = []

    def receive(self, iv, ciphertext):
        decryptor = Cipher(
            algorithms.AES(self.key), modes.CTR(iv)
        ).decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        command = json.loads(plaintext)

        # Simulate processing only; do not execute commands or modify files.
        self.processed.append(command)
        print(f"Processed #{len(self.processed)}: {plaintext.decode()}")
        return command


def main():
    key = os.urandom(32)
    iv = os.urandom(16)
    ciphertext = encrypt(key, iv, COMMAND)
    receiver = Receiver(key)

    print("Original command:", COMMAND.decode())
    print("\n--- Bit-flip attack: READ -> EDIT ---")
    offset = COMMAND.index(b"READ")
    modified = relay(ciphertext, offset, b"READ", b"EDIT")

    print("Original ciphertext:", ciphertext.hex())
    print("Modified ciphertext:", modified.hex())

    first = receiver.receive(iv, modified)
    assert first == {"action": "EDIT", "path": "notes.txt"}

    print("\n--- Replay the identical modified ciphertext ---")
    second = receiver.receive(iv, modified)
    assert second == first
    assert len(receiver.processed) == 2
    print("Replay accepted: the same command was processed twice.")


if __name__ == "__main__":
    main()
