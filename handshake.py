"""Task 2: local authenticated ephemeral Diffie-Hellman handshake."""

import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import dh, padding, rsa


BASE = Path(__file__).resolve().parent
PROTOCOL = b"CSCE465-HS-v2"
GROUP = b"ffdhe3072"
ROLES = (b"gateway", b"node")
WIDTH = 384

# Exact field order:
# label, group, gateway identity, node identity,
# gateway DH public value, node DH public value,
# gateway nonce, node nonce.
FIELD_LENGTHS = (
    len(PROTOCOL), len(GROUP), len(b"gateway"), len(b"node"),
    WIDTH, WIDTH, 16, 16,
)


class HandshakeError(Exception):
    """The session must not be accepted."""


def sha256(data):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()


def mac(key, data):
    signer = hmac.HMAC(key, hashes.SHA256())
    signer.update(data)
    return signer.finalize()


def pss():
    return padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.DIGEST_LENGTH,
    )


def encode_fields(fields):
    return b"".join(
        len(field).to_bytes(4, "big") + field
        for field in fields
    )


def parse_transcript(data):
    """Reject malformed lengths and unexpected identities before hashing."""
    if not isinstance(data, bytes):
        raise HandshakeError("transcript must be bytes")

    fields = []
    position = 0

    for expected_length in FIELD_LENGTHS:
        if position + 4 > len(data):
            raise HandshakeError("missing field length")

        length = int.from_bytes(data[position:position + 4], "big")
        position += 4

        if length != expected_length:
            raise HandshakeError("incorrect field length")
        if position + length > len(data):
            raise HandshakeError("truncated field")

        fields.append(data[position:position + length])
        position += length

    if position != len(data):
        raise HandshakeError("trailing transcript data")
    if fields[0] != PROTOCOL or fields[1] != GROUP:
        raise HandshakeError("unexpected protocol or group")
    if tuple(fields[2:4]) != ROLES:
        raise HandshakeError("unexpected peer identity")

    return tuple(fields)


def build_transcript(gateway_offer, node_offer):
    gateway_public, gateway_nonce = gateway_offer
    node_public, node_nonce = node_offer

    transcript = encode_fields((
        PROTOCOL, GROUP, b"gateway", b"node",
        gateway_public, node_public,
        gateway_nonce, node_nonce,
    ))
    parse_transcript(transcript)
    return transcript


def load_parameters():
    # This is the trusted ffdhe3072 file generated and checked in Task 0.
    parameters = serialization.load_pem_parameters(
        (BASE / "ffdhe3072.pem").read_bytes()
    )
    if not isinstance(parameters, dh.DHParameters):
        raise HandshakeError("expected DH parameters")

    numbers = parameters.parameter_numbers()
    if numbers.p.bit_length() != 3072 or numbers.g != 2:
        raise HandshakeError("unexpected DH parameters")
    return parameters


def derive_keys(shared_secret, transcript_hash):
    # Fixed-width, zero-padded big-endian encoding required by the task.
    z = int.from_bytes(shared_secret, "big").to_bytes(WIDTH, "big")
    master = sha256(b"CSCE465-KDF-v1" + z + transcript_hash)

    labels = {
        "g2n_enc": b"gateway-to-node encryption",
        "g2n_mac": b"gateway-to-node MAC",
        "n2g_enc": b"node-to-gateway encryption",
        "n2g_mac": b"node-to-gateway MAC",
    }
    keys = {
        name: mac(master, label + transcript_hash)
        for name, label in labels.items()
    }
    keys["session_id"] = mac(
        master, b"session identifier" + transcript_hash
    )[:8]
    return keys


class Party:
    """One handshake attempt; create a new Party for every new session."""

    def __init__(self, role, parameters):
        if role not in ROLES:
            raise HandshakeError("unknown role")

        self.role = role
        self.peer_role = b"node" if role == b"gateway" else b"gateway"
        self.parameters = parameters

        own_name = self.role.decode()
        peer_name = self.peer_role.decode()

        self.signing_key = serialization.load_pem_private_key(
            (BASE / "keys" / f"{own_name}_private.pem").read_bytes(),
            password=None,
        )
        # Trust comes from local configuration, not a key sent by the peer.
        self.peer_key = serialization.load_pem_public_key(
            (BASE / "keys" / f"{peer_name}_public.pem").read_bytes()
        )

        if not isinstance(self.signing_key, rsa.RSAPrivateKey):
            raise HandshakeError("expected RSA signing key")
        if not isinstance(self.peer_key, rsa.RSAPublicKey):
            raise HandshakeError("expected RSA peer key")
        if self.signing_key.key_size != 3072 or self.peer_key.key_size != 3072:
            raise HandshakeError("RSA keys must be 3072 bits")

        self._dh_private = parameters.generate_private_key()
        self.public_value = (
            self._dh_private.public_key().public_numbers().y
        ).to_bytes(WIDTH, "big")
        self.nonce = os.urandom(16)
        self._signed_transcript = None
        self._closed = False

    def offer(self):
        return self.public_value, self.nonce

    def _validate(self, transcript):
        if self._closed:
            raise HandshakeError("handshake attempt already closed")

        fields = parse_transcript(transcript)
        own_index = 0 if self.role == b"gateway" else 1

        if fields[4 + own_index] != self.public_value:
            raise HandshakeError("local DH public value changed")
        if fields[6 + own_index] != self.nonce:
            raise HandshakeError("local nonce changed")

        if fields[4] == fields[5]:
            raise HandshakeError("reflected DH public value")

        return fields

    def sign(self, transcript):
        self._validate(transcript)

        if self._signed_transcript is not None:
            raise HandshakeError("this attempt already signed a transcript")

        signature = self.signing_key.sign(
            self.role + sha256(transcript),
            pss(),
            hashes.SHA256(),
        )
        self._signed_transcript = transcript
        return signature

    def finish(self, transcript, peer_signature):
        """Return keys only after authentication; consume this attempt."""
        if self._closed:
            raise HandshakeError("handshake attempt already closed")

        try:
            fields = self._validate(transcript)
            if transcript != self._signed_transcript:
                raise HandshakeError("transcript differs from signed transcript")

            transcript_hash = sha256(transcript)

            try:
                self.peer_key.verify(
                    peer_signature,
                    self.peer_role + transcript_hash,
                    pss(),
                    hashes.SHA256(),
                )
            except InvalidSignature as exc:
                raise HandshakeError("invalid peer signature") from exc

            peer_index = 1 if self.role == b"gateway" else 0
            peer_value = int.from_bytes(fields[4 + peer_index], "big")

            try:
                peer_public = dh.DHPublicNumbers(
                    peer_value, self.parameters.parameter_numbers()
                ).public_key()
                shared_secret = self._dh_private.exchange(peer_public)
            except ValueError as exc:
                raise HandshakeError("invalid peer DH public value") from exc

            return derive_keys(shared_secret, transcript_hash)
        finally:
            self._closed = True
            # Release our reference; Python does not guarantee memory erasure.
            self._dh_private = None


def run_handshake():
    parameters = load_parameters()
    gateway = Party(b"gateway", parameters)
    node = Party(b"node", parameters)

    transcript = build_transcript(gateway.offer(), node.offer())
    gateway_signature = gateway.sign(transcript)
    node_signature = node.sign(transcript)

    gateway_keys = gateway.finish(transcript, node_signature)
    node_keys = node.finish(transcript, gateway_signature)
    return gateway_keys, node_keys


def main():
    gateway_keys, node_keys = run_handshake()
    assert gateway_keys == node_keys
    assert len(gateway_keys["session_id"]) == 8

    names = ("g2n_enc", "g2n_mac", "n2g_enc", "n2g_mac")
    assert all(len(gateway_keys[name]) == 32 for name in names)
    assert len({gateway_keys[name] for name in names}) == 4

    print("Handshake accepted by both parties.")
    print("Both parties derived identical session keys.")
    print("Four distinct 32-byte traffic keys derived.")
    print("Session ID:", gateway_keys["session_id"].hex())

    fresh_gateway, fresh_node = run_handshake()
    assert fresh_gateway == fresh_node
    assert fresh_gateway["session_id"] != gateway_keys["session_id"]
    assert all(fresh_gateway[name] != gateway_keys[name] for name in names)
    print("Second session derived fresh keys and a different session ID.")


if __name__ == "__main__":
    main()
