import pytest

import secure_record as sr
from handshake import run_handshake


@pytest.fixture(scope="module")
def session_keys():
    # Establish keys once to keep these record-layer tests fast.
    return run_handshake()


@pytest.fixture
def endpoints(session_keys):
    # Each test is an isolated simulation with fresh counters.
    # Production code must never reset counters with existing keys.
    gateway_keys, node_keys = session_keys
    return (
        sr.RecordState("gateway", gateway_keys),
        sr.RecordState("node", node_keys),
    )


def flip_byte(data, index):
    changed = bytearray(data)
    changed[index] ^= 1
    return bytes(changed)


def test_bidirectional_messages(endpoints):
    gateway, node = endpoints

    request = sr.seal(gateway, b"request", message_type=1)
    reply = sr.seal(node, b"reply", message_type=2)

    assert sr.open_record(node, request) == (1, b"request")
    assert sr.open_record(gateway, reply) == (2, b"reply")
    assert gateway.send_sequence == gateway.receive_sequence == 1
    assert node.send_sequence == node.receive_sequence == 1


@pytest.mark.parametrize(
    "index",
    [
        sr.HEADER.size + sr.IV_SIZE,  # Ciphertext.
        10,                         # Authenticated message-type header.
        sr.HEADER.size,             # IV.
        -1,                         # MAC tag.
    ],
    ids=["ciphertext", "header", "iv", "tag"],
)
def test_tampering_rejected_before_decryption(endpoints, monkeypatch, index):
    gateway, node = endpoints
    original = sr.seal(gateway, b"hello")
    modified = flip_byte(original, index)

    def forbidden_cipher(*args, **kwargs):
        pytest.fail("Cipher was constructed before rejecting the bad MAC")

    # Seal first, then prevent any attempt to construct a decryptor.
    with monkeypatch.context() as patch:
        patch.setattr(sr, "Cipher", forbidden_cipher)
        with pytest.raises(sr.RecordError, match="invalid record MAC"):
            sr.open_record(node, modified)

    assert node.receive_sequence == 0
    assert sr.open_record(node, original) == (1, b"hello")


def test_replay_rejected(endpoints):
    gateway, node = endpoints
    record = sr.seal(gateway, b"hello")
    assert sr.open_record(node, record) == (1, b"hello")

    with pytest.raises(sr.RecordError, match="unexpected sequence number"):
        sr.open_record(node, record)

    assert node.receive_sequence == 1


def test_reflection_rejected(endpoints):
    gateway, _ = endpoints
    record = sr.seal(gateway, b"hello")

    with pytest.raises(sr.RecordError, match="invalid record MAC"):
        sr.open_record(gateway, record)

    assert gateway.receive_sequence == 0


def test_out_of_order_rejected_without_advancing_state(endpoints):
    gateway, node = endpoints
    first = sr.seal(gateway, b"first")
    second = sr.seal(gateway, b"second")

    with pytest.raises(sr.RecordError, match="unexpected sequence number"):
        sr.open_record(node, second)

    assert node.receive_sequence == 0
    assert sr.open_record(node, first) == (1, b"first")
    assert sr.open_record(node, second) == (1, b"second")


@pytest.mark.parametrize("change", ["short", "truncated", "extra"])
def test_malformed_record(endpoints, change):
    gateway, node = endpoints
    record = sr.seal(gateway, b"hello")

    if change == "short":
        malformed = record[:10]
        reason = "truncated record"
    elif change == "truncated":
        malformed = record[:-1]
        reason = "record length mismatch"
    else:
        malformed = record + b"x"
        reason = "record length mismatch"

    with pytest.raises(sr.RecordError, match=reason):
        sr.open_record(node, malformed)

    assert node.receive_sequence == 0


@pytest.mark.parametrize(
    "field_index, replacement, reason",
    [
        (0, 2, "unsupported record version"),
        (1, sr.NODE_TO_GATEWAY, "wrong record direction"),
    ],
)
def test_authenticated_invalid_header(
    endpoints, field_index, replacement, reason
):
    gateway, node = endpoints
    record = sr.seal(gateway, b"hello")
    fields = list(sr.HEADER.unpack(record[:sr.HEADER.size]))
    fields[field_index] = replacement

    # Test-only use of the key isolates the semantic header checks:
    # even a correctly authenticated record must use valid fields.
    body = (
        sr.HEADER.pack(*fields)
        + record[sr.HEADER.size:-sr.TAG_SIZE]
    )
    modified = body + sr.make_tag(gateway.send_mac, body)

    with pytest.raises(sr.RecordError, match=reason):
        sr.open_record(node, modified)

    assert node.receive_sequence == 0


def test_authenticated_wrong_iv(endpoints):
    gateway, node = endpoints
    record = sr.seal(gateway, b"hello")
    body = flip_byte(record[:-sr.TAG_SIZE], sr.HEADER.size)
    modified = body + sr.make_tag(gateway.send_mac, body)

    with pytest.raises(sr.RecordError, match="unexpected record IV"):
        sr.open_record(node, modified)

    assert node.receive_sequence == 0


def test_empty_plaintext(endpoints):
    gateway, node = endpoints
    record = sr.seal(gateway, b"", message_type=0)
    assert sr.open_record(node, record) == (0, b"")


def test_sequence_and_iv_encoding(endpoints):
    gateway, node = endpoints
    observed_ivs = []

    for sequence in range(3):
        record = sr.seal(gateway, b"hello")
        header = sr.HEADER.unpack(record[:sr.HEADER.size])
        iv = record[sr.HEADER.size:sr.HEADER.size + sr.IV_SIZE]

        assert header == (1, sr.GATEWAY_TO_NODE, sequence, 1, 5)
        assert iv == gateway.session_id + sequence.to_bytes(8, "big")
        observed_ivs.append(iv)
        assert sr.open_record(node, record) == (1, b"hello")

    assert len(set(observed_ivs)) == 3


def test_send_sequence_exhaustion(endpoints):
    gateway, _ = endpoints
    gateway.send_sequence = sr.SEQUENCE_LIMIT - 1

    last = sr.seal(gateway, b"last")
    assert sr.HEADER.unpack(last[:sr.HEADER.size])[2] == (
        sr.SEQUENCE_LIMIT - 1
    )

    with pytest.raises(sr.RecordError, match="send sequence exhausted"):
        sr.seal(gateway, b"must not wrap")


def test_separate_directional_keys(endpoints):
    gateway, node = endpoints

    assert gateway.send_enc == node.receive_enc
    assert gateway.send_mac == node.receive_mac
    assert node.send_enc == gateway.receive_enc
    assert node.send_mac == gateway.receive_mac
    assert len({
        gateway.send_enc,
        gateway.send_mac,
        gateway.receive_enc,
        gateway.receive_mac,
    }) == 4
