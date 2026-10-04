import pytest

from handshake import (
    HandshakeError,
    Party,
    build_transcript,
    encode_fields,
    load_parameters,
    parse_transcript,
    run_handshake,
)


@pytest.fixture(scope="module")
def parameters():
    return load_parameters()


def make_pair(parameters):
    gateway = Party(b"gateway", parameters)
    node = Party(b"node", parameters)
    transcript = build_transcript(gateway.offer(), node.offer())
    return gateway, node, transcript


def flip_first_byte(value):
    return bytes([value[0] ^ 1]) + value[1:]


def test_valid_handshake():
    gateway_keys, node_keys = run_handshake()
    assert gateway_keys == node_keys
    assert len(gateway_keys["session_id"]) == 8

    names = ("g2n_enc", "g2n_mac", "n2g_enc", "n2g_mac")
    assert all(len(gateway_keys[name]) == 32 for name in names)
    assert len({gateway_keys[name] for name in names}) == 4


def test_fresh_session_keys():
    first, _ = run_handshake()
    second, _ = run_handshake()

    for name in first:
        assert first[name] != second[name]


@pytest.mark.parametrize(
    "field_index, reason",
    [
        (4, "local DH public value changed"),
        (6, "local nonce changed"),
    ],
)
def test_changed_local_fields(parameters, field_index, reason):
    gateway, _, transcript = make_pair(parameters)
    fields = list(parse_transcript(transcript))
    fields[field_index] = flip_first_byte(fields[field_index])
    changed = encode_fields(fields)

    with pytest.raises(HandshakeError, match=reason):
        gateway.sign(changed)


@pytest.mark.parametrize("field_index", [5, 7])
def test_changed_peer_fields_break_signature(parameters, field_index):
    gateway, node, transcript = make_pair(parameters)
    original_node_signature = node.sign(transcript)

    fields = list(parse_transcript(transcript))
    fields[field_index] = flip_first_byte(fields[field_index])
    changed = encode_fields(fields)

    # Gateway sees the altered peer value and signs that transcript.
    # The original node signature must not authenticate it.
    gateway.sign(changed)

    with pytest.raises(HandshakeError, match="invalid peer signature"):
        gateway.finish(changed, original_node_signature)


def test_incorrect_declared_length(parameters):
    gateway, _, transcript = make_pair(parameters)
    declared = int.from_bytes(transcript[:4], "big")
    malformed = (declared + 1).to_bytes(4, "big") + transcript[4:]

    with pytest.raises(HandshakeError, match="incorrect field length"):
        gateway.sign(malformed)


def test_truncated_transcript(parameters):
    gateway, _, transcript = make_pair(parameters)

    with pytest.raises(HandshakeError, match="truncated field"):
        gateway.sign(transcript[:-1])


def test_trailing_transcript_data(parameters):
    gateway, _, transcript = make_pair(parameters)

    with pytest.raises(HandshakeError, match="trailing transcript data"):
        gateway.sign(transcript + b"x")


def test_unexpected_identity(parameters):
    gateway, _, transcript = make_pair(parameters)
    fields = list(parse_transcript(transcript))
    fields[3] = b"evil"  # Same length as "node".
    changed = encode_fields(fields)

    with pytest.raises(HandshakeError, match="unexpected peer identity"):
        gateway.sign(changed)


def test_invalid_signature(parameters):
    gateway, node, transcript = make_pair(parameters)
    gateway.sign(transcript)
    bad_signature = flip_first_byte(node.sign(transcript))

    with pytest.raises(HandshakeError, match="invalid peer signature"):
        gateway.finish(transcript, bad_signature)

    # Failed attempts cannot subsequently be accepted.
    with pytest.raises(HandshakeError, match="already closed"):
        gateway.finish(transcript, bad_signature)


def test_incorrect_peer_public_key(parameters):
    gateway, node, transcript = make_pair(parameters)
    gateway.sign(transcript)
    node_signature = node.sign(transcript)

    # Simulate configuring the wrong trusted RSA public key.
    gateway.peer_key = gateway.signing_key.public_key()

    with pytest.raises(HandshakeError, match="invalid peer signature"):
        gateway.finish(transcript, node_signature)


def test_reflected_signature(parameters):
    gateway, _, transcript = make_pair(parameters)
    gateway_signature = gateway.sign(transcript)

    with pytest.raises(HandshakeError, match="invalid peer signature"):
        gateway.finish(transcript, gateway_signature)


def test_role_binding_even_with_same_rsa_key(parameters):
    gateway, _, transcript = make_pair(parameters)
    gateway_signature = gateway.sign(transcript)

    # Isolate the role check: even with the same verification key,
    # a gateway signature must not verify as a node signature.
    gateway.peer_key = gateway.signing_key.public_key()

    with pytest.raises(HandshakeError, match="invalid peer signature"):
        gateway.finish(transcript, gateway_signature)


def test_reflected_dh_offer(parameters):
    gateway = Party(b"gateway", parameters)
    transcript = build_transcript(gateway.offer(), gateway.offer())

    with pytest.raises(HandshakeError, match="reflected DH public value"):
        gateway.sign(transcript)


def test_old_transcript_rejected_by_new_session(parameters):
    _, _, old_transcript = make_pair(parameters)
    fresh_gateway = Party(b"gateway", parameters)

    with pytest.raises(HandshakeError, match="local DH public value changed"):
        fresh_gateway.sign(old_transcript)


def test_completed_handshake_cannot_be_reused(parameters):
    gateway, node, transcript = make_pair(parameters)
    gateway.sign(transcript)
    node_signature = node.sign(transcript)
    gateway.finish(transcript, node_signature)

    with pytest.raises(HandshakeError, match="already closed"):
        gateway.finish(transcript, node_signature)
