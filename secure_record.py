"""Task 3: assignment-specified AES-CTR encrypt-then-MAC records."""

import struct
from threading import Lock

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from handshake import run_handshake


VERSION = 1
GATEWAY_TO_NODE = 0
NODE_TO_GATEWAY = 1

# version(1), direction(1), sequence(8), type(1), ciphertext length(4)
HEADER = struct.Struct("!BBQBI")
IV_SIZE = 16
TAG_SIZE = 32
SEQUENCE_LIMIT = 1 << 64


class RecordError(Exception):
    """Record rejected; no plaintext is returned."""


class RecordState:
    """One state per endpoint per session. Never reset or clone live state."""

    def __init__(self, role, keys):
        if role not in ("gateway", "node"):
            raise ValueError("role must be gateway or node")

        names = ("g2n_enc", "g2n_mac", "n2g_enc", "n2g_mac")
        for name in names:
            if not isinstance(keys[name], bytes) or len(keys[name]) != 32:
                raise ValueError("traffic keys must be 32-byte values")

        if len({keys[name] for name in names}) != 4:
            raise ValueError("traffic keys must be distinct")

        session_id = keys["session_id"]
        if not isinstance(session_id, bytes) or len(session_id) != 8:
            raise ValueError("session ID must be 8 bytes")

        self.session_id = session_id

        if role == "gateway":
            send_prefix, receive_prefix = "g2n", "n2g"
            self.send_direction = GATEWAY_TO_NODE
            self.receive_direction = NODE_TO_GATEWAY
        else:
            send_prefix, receive_prefix = "n2g", "g2n"
            self.send_direction = NODE_TO_GATEWAY
            self.receive_direction = GATEWAY_TO_NODE

        self.send_enc = keys[f"{send_prefix}_enc"]
        self.send_mac = keys[f"{send_prefix}_mac"]
        self.receive_enc = keys[f"{receive_prefix}_enc"]
        self.receive_mac = keys[f"{receive_prefix}_mac"]

        self.send_sequence = 0
        self.receive_sequence = 0
        self._send_lock = Lock()
        self._receive_lock = Lock()


def make_tag(key, authenticated_bytes):
    signer = hmac.HMAC(key, hashes.SHA256())
    signer.update(authenticated_bytes)
    return signer.finalize()


def seal(state, plaintext, message_type=1):
    """Return header || IV || ciphertext || tag."""
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")
    if type(message_type) is not int or not 0 <= message_type <= 255:
        raise ValueError("message type must be an integer from 0 to 255")
    if len(plaintext) > 0xFFFFFFFF:
        raise ValueError("plaintext exceeds the record length field")

    with state._send_lock:
        sequence = state.send_sequence
        if not 0 <= sequence < SEQUENCE_LIMIT:
            raise RecordError("send sequence exhausted; start a new session")

        header = HEADER.pack(
            VERSION,
            state.send_direction,
            sequence,
            message_type,
            len(plaintext),
        )
        iv = state.session_id + sequence.to_bytes(8, "big")

        # Reserve this sequence before encryption so an exception cannot
        # cause the same IV to be used for a different encryption attempt.
        state.send_sequence += 1

        encryptor = Cipher(
            algorithms.AES(state.send_enc), modes.CTR(iv)
        ).encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        authenticated_bytes = header + iv + ciphertext
        return authenticated_bytes + make_tag(
            state.send_mac, authenticated_bytes
        )


def open_record(state, record):
    """Return (message_type, plaintext) only after every check succeeds."""
    if not isinstance(record, bytes):
        raise RecordError("record must be bytes")

    with state._receive_lock:
        if len(record) < HEADER.size + IV_SIZE + TAG_SIZE:
            raise RecordError("truncated record")

        header = record[:HEADER.size]
        version, direction, sequence, message_type, length = (
            HEADER.unpack(header)
        )

        expected_size = HEADER.size + IV_SIZE + length + TAG_SIZE
        if len(record) != expected_size:
            raise RecordError("record length mismatch")

        iv_start = HEADER.size
        ciphertext_start = iv_start + IV_SIZE
        iv = record[iv_start:ciphertext_start]
        ciphertext = record[ciphertext_start:-TAG_SIZE]
        tag = record[-TAG_SIZE:]

        # Library verification performs the constant-time MAC comparison.
        verifier = hmac.HMAC(state.receive_mac, hashes.SHA256())
        verifier.update(record[:-TAG_SIZE])
        try:
            verifier.verify(tag)
        except InvalidSignature as exc:
            raise RecordError("invalid record MAC") from exc

        # Authentication and all protocol checks precede decryption.
        if version != VERSION:
            raise RecordError("unsupported record version")
        if direction != state.receive_direction:
            raise RecordError("wrong record direction")
        if state.receive_sequence >= SEQUENCE_LIMIT:
            raise RecordError("receive sequence exhausted")
        if sequence != state.receive_sequence:
            raise RecordError("unexpected sequence number")

        expected_iv = state.session_id + sequence.to_bytes(8, "big")
        if iv != expected_iv:
            raise RecordError("unexpected record IV")

        decryptor = Cipher(
            algorithms.AES(state.receive_enc), modes.CTR(iv)
        ).decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        state.receive_sequence += 1
        return message_type, plaintext


def expect_rejection(label, state, record, expected_reason):
    try:
        open_record(state, record)
    except RecordError as exc:
        assert str(exc) == expected_reason
        print(f"{label} rejected: {exc}")
    else:
        raise AssertionError(f"{label} was incorrectly accepted")


def main():
    gateway_keys, node_keys = run_handshake()
    gateway = RecordState("gateway", gateway_keys)
    node = RecordState("node", node_keys)

    command = b'{"action":"READ","path":"notes.txt"}'
    request = seal(gateway, command, message_type=1)
    received_type, received = open_record(node, request)
    assert (received_type, received) == (1, command)
    print("Node received:", received.decode())

    reply = seal(node, b'{"status":"OK"}', message_type=2)
    received_type, received = open_record(gateway, reply)
    assert (received_type, received) == (2, b'{"status":"OK"}')
    print("Gateway received:", received.decode())

    expect_rejection(
        "Replay", node, request, "unexpected sequence number"
    )

    # Use the next valid record to demonstrate rejection of tampering.
    next_request = seal(gateway, b"next message")
    modified = bytearray(next_request)
    modified[HEADER.size + IV_SIZE] ^= 1
    expect_rejection(
        "Modified ciphertext", node, bytes(modified), "invalid record MAC"
    )

    # A rejected record must not advance the receiver's sequence counter.
    assert open_record(node, next_request) == (1, b"next message")
    print("Original next record accepted after tampering was rejected.")

    # Send a gateway-originated record back toward the gateway.
    expect_rejection(
        "Reflected record", gateway, request, "invalid record MAC"
    )
    print("Task 3 demonstration completed.")


if __name__ == "__main__":
    main()
