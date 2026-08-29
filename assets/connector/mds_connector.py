#!/usr/bin/env python3
"""Connect a tool or machine to My (Social) Data Space.

This program runs on a computer beside the machine you want to read — a camera
system, a sensor hub, a server, a script — and carries its readings into a
topic on your phone. It never gets more than the phone granted it: you approve
a topic, the fields, a rate and an end date, and this program cannot widen any
of that.

    python3 mds_connector.py profiles
    python3 mds_connector.py fields  --profile frigate
    python3 mds_connector.py preview --profile frigate
    python3 mds_connector.py connect --profile frigate --topic <topic id> \
        --invite 'mds-tool-invite.v1....'
    python3 mds_connector.py run     --profile frigate --topic <topic id>

The machine-specific part is a JSON profile, not code: it says where the
records live, how to sign in, and how one record becomes one entry. The
mapping vocabulary is a closed set of rules on purpose — a mapping that can
express anything is a scripting language with a worse editor, and nobody can
review it.

Credentials are never written into a profile. A profile names KEYS; the values
come from the environment (MDS_<KEY>) or from a credentials file only you can
read.

Requires: Python 3.9+ and the `cryptography` package (pip install cryptography).
"""

from __future__ import annotations

import argparse
import base64
import datetime as _dt
import hashlib
import hmac
import json
import os
import random
import re
import socket
import ssl
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Iterable

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
except ImportError:  # pragma: no cover - the message is the whole point
    sys.stderr.write(
        "This connector needs the `cryptography` package.\n"
        "Install it with:  python3 -m pip install --user cryptography\n"
    )
    raise SystemExit(69)


# --- the wire vocabulary, shared with the app -------------------------------

PROTOCOL_VERSION = "mds/1"
INVITE_SCHEME = "mds-tool-invite.v1."
INVITE_MAX_ENCODED = 512

# Frozen in the app's contract; a command outside these windows is refused.
MAX_COMMAND_AGE = _dt.timedelta(minutes=5)
MAX_FUTURE_SKEW = _dt.timedelta(seconds=30)
MAX_BACKDATE = _dt.timedelta(days=30)

MAX_HEADER_BYTES = 512 * 1024
MAX_PAYLOAD_BYTES = 4 * 1024 * 1024


class Refused(Exception):
    """Something a person can read and act on, not a stack trace."""


# --- small shared readings --------------------------------------------------


def b64url(raw: bytes) -> str:
    """Padded base64url, exactly as the app writes it."""
    return base64.urlsafe_b64encode(raw).decode("ascii")


def unb64url(text: str) -> bytes:
    """Padding-tolerant, because the encoding travels as text."""
    padded = text + "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def compact_json(value: Any) -> str:
    """One JSON spelling for everything this program hashes or signs."""
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def utc_now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def wire_time(at: _dt.datetime) -> str:
    """The exact instant spelling the app's parser accepts and reproduces.

    Truncated to whole milliseconds on purpose. The app compares the bytes this
    program signed against its own re-rendering of the same claim, and its
    renderer writes three fractional digits when there are no microseconds and
    six when there are. Staying on a millisecond boundary means one spelling.
    """
    at = at.astimezone(_dt.timezone.utc).replace(microsecond=(at.microsecond // 1000) * 1000)
    return at.strftime("%Y-%m-%dT%H:%M:%S.") + f"{at.microsecond // 1000:03d}" + "Z"


def parse_wire_time(text: Any) -> _dt.datetime | None:
    """An instant that carries its zone, or nothing.

    A zoneless string would mean different instants on two machines, and an
    expiry that moves with the reader's clock is not an expiry.
    """
    if not isinstance(text, str) or not text or len(text) > 40:
        return None
    candidate = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = _dt.datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(_dt.timezone.utc)


def canonical(value: Any) -> Any:
    """THE canonical form for everything signed here.

    Keys sorted at every level and absent values omitted, so two encoders that
    agree on the claim agree on what was claimed. The app carries the exact
    signed bytes beside the signature and compares the readable claim against
    what those bytes say, which is what lets a tool written in another language
    sign at all.
    """
    if isinstance(value, dict):
        return {key: canonical(value[key]) for key in sorted(value) if value[key] is not None}
    if isinstance(value, list):
        return [canonical(item) for item in value]
    return value


def canonical_bytes(claim: dict) -> bytes:
    return compact_json(canonical(claim)).encode("utf-8")


# --- crypto -----------------------------------------------------------------
#
# Nothing here is invented. X25519 for key agreement, Ed25519 for signatures
# and XChaCha20-Poly1305 for payloads, the same three the app uses. The only
# piece written out longhand is HChaCha20, the key-derivation step that turns
# ChaCha20-Poly1305 into its extended-nonce form: `cryptography` ships the AEAD
# but not that step, and it is a fixed, published permutation with published
# test vectors, which `_self_test` checks before anything is sealed with it.

_CHACHA_CONSTANTS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)
_MASK32 = 0xFFFFFFFF


def _rotl32(value: int, count: int) -> int:
    return ((value << count) | (value >> (32 - count))) & _MASK32


def _quarter_round(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & _MASK32
    state[d] = _rotl32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & _MASK32
    state[b] = _rotl32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & _MASK32
    state[d] = _rotl32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & _MASK32
    state[b] = _rotl32(state[b] ^ state[c], 7)


def hchacha20(key: bytes, nonce16: bytes) -> bytes:
    """The subkey XChaCha20 derives from the first sixteen nonce bytes."""
    if len(key) != 32 or len(nonce16) != 16:
        raise ValueError("hchacha20 takes a 32-byte key and a 16-byte nonce")
    state = list(_CHACHA_CONSTANTS)
    state += [int.from_bytes(key[i : i + 4], "little") for i in range(0, 32, 4)]
    state += [int.from_bytes(nonce16[i : i + 4], "little") for i in range(0, 16, 4)]
    for _ in range(10):
        _quarter_round(state, 0, 4, 8, 12)
        _quarter_round(state, 1, 5, 9, 13)
        _quarter_round(state, 2, 6, 10, 14)
        _quarter_round(state, 3, 7, 11, 15)
        _quarter_round(state, 0, 5, 10, 15)
        _quarter_round(state, 1, 6, 11, 12)
        _quarter_round(state, 2, 7, 8, 13)
        _quarter_round(state, 3, 4, 9, 14)
    words = state[0:4] + state[12:16]
    return b"".join(word.to_bytes(4, "little") for word in words)


def xchacha20poly1305_encrypt(key: bytes, nonce24: bytes, plaintext: bytes) -> bytes:
    """Ciphertext with its 16-byte tag appended. No associated data, like the app."""
    subkey = hchacha20(key, nonce24[:16])
    return ChaCha20Poly1305(subkey).encrypt(b"\x00\x00\x00\x00" + nonce24[16:24], plaintext, None)


def xchacha20poly1305_decrypt(key: bytes, nonce24: bytes, sealed: bytes) -> bytes:
    subkey = hchacha20(key, nonce24[:16])
    return ChaCha20Poly1305(subkey).decrypt(b"\x00\x00\x00\x00" + nonce24[16:24], sealed, None)


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


DID_PREFIX = "did:key:z"
_DID_KEY_CHARS = 43


def did_for(signing_public_key: bytes) -> str:
    """The pre-release actor id the app mints. Key-derived and locally checkable."""
    return DID_PREFIX + b64url(signing_public_key).rstrip("=")


def public_key_from_did(did: Any) -> bytes | None:
    """The signing key a DID encodes, refusing every other spelling of it.

    One public key must have one actor identifier: accepting a padded or
    otherwise equivalent encoding would let one key answer to two DIDs.
    """
    if not isinstance(did, str):
        return None
    if not did.startswith(DID_PREFIX) or len(did) != len(DID_PREFIX) + _DID_KEY_CHARS:
        return None
    try:
        raw = unb64url(did[len(DID_PREFIX) :])
    except Exception:
        return None
    if len(raw) != 32 or did_for(raw) != did:
        return None
    return raw


def verify_signature(payload: bytes, signature_b64: Any, did: Any) -> bool:
    """A malformed signature is a failed verification, never a crash."""
    key = public_key_from_did(did)
    if key is None or not isinstance(signature_b64, str) or not signature_b64:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(unb64url(signature_b64), payload)
        return True
    except Exception:
        return False


class PodKeys:
    """The keypair that *is* this tool's identity.

    Two keypairs, not one: Ed25519 proves what this tool wrote, X25519 lets the
    phone seal an answer to it. Reusing one for both is a well-known way to
    weaken both.
    """

    def __init__(self, signing_seed: bytes, exchange_seed: bytes) -> None:
        if len(signing_seed) != 32 or len(exchange_seed) != 32:
            raise Refused("this tool's stored key material is not the right size")
        self.signing_seed = signing_seed
        self.exchange_seed = exchange_seed
        self._signing = Ed25519PrivateKey.from_private_bytes(signing_seed)
        self._exchange = X25519PrivateKey.from_private_bytes(exchange_seed)
        self.signing_public_key = self._signing.public_key().public_bytes_raw()
        self.exchange_public_key = self._exchange.public_key().public_bytes_raw()
        self.did = did_for(self.signing_public_key)

    @staticmethod
    def generate() -> "PodKeys":
        return PodKeys(os.urandom(32), os.urandom(32))

    @property
    def encoded_exchange_key(self) -> str:
        return b64url(self.exchange_public_key)

    def sign(self, payload: bytes) -> str:
        return b64url(self._signing.sign(payload))

    def shared_secret(self, peer_exchange_key: bytes) -> bytes:
        return self._exchange.exchange(X25519PublicKey.from_public_bytes(peer_exchange_key))


def decode_sealed_address(encoded: Any) -> bytes | None:
    """One encoded X25519 address as bytes, or nothing.

    The BYTES are what identify a key, so comparing encoded strings would make
    two spellings of one address look like two addresses.
    """
    if not isinstance(encoded, str) or not encoded:
        return None
    try:
        raw = unb64url(encoded)
    except Exception:
        return None
    return raw if len(raw) == 32 else None


class DecryptionFailed(Exception):
    """Deliberately says nothing about why. Telling 'wrong key' from 'tampered'
    is the signal a padding-oracle attack is built on."""


def seal_envelope(
    payload: dict, sender: PodKeys, recipient_did: str, recipient_exchange_key: bytes
) -> dict:
    """Ciphertext addressed to one recipient AND signed, so they know who sealed it."""
    ephemeral = X25519PrivateKey.generate()
    shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(recipient_exchange_key))
    nonce = os.urandom(24)
    boxed = xchacha20poly1305_encrypt(shared, nonce, compact_json(payload).encode("utf-8"))
    ciphertext = b64url(boxed[:-16])
    return {
        "recipient_did": recipient_did,
        "sender_did": sender.did,
        "epk": b64url(ephemeral.public_key().public_bytes_raw()),
        "nonce": b64url(nonce),
        "ciphertext": ciphertext,
        "mac": b64url(boxed[-16:]),
        "signature": sender.sign(ciphertext.encode("utf-8")),
    }


def open_envelope(envelope: Any, recipient: PodKeys) -> dict:
    """Opens an envelope addressed to us, refusing anything unsigned.

    The signature is checked BEFORE any decryption and before `sender_did` is
    believed: that field is a plain string, so an envelope that simply omitted
    a signature would let anybody deliver a message appearing to come from
    somebody else.
    """
    if not isinstance(envelope, dict):
        raise DecryptionFailed()
    signature = envelope.get("signature")
    sender_did = envelope.get("sender_did")
    ciphertext = envelope.get("ciphertext")
    if envelope.get("recipient_did") != recipient.did:
        raise DecryptionFailed()
    if not isinstance(signature, str) or not isinstance(ciphertext, str):
        raise DecryptionFailed()
    if not verify_signature(ciphertext.encode("utf-8"), signature, sender_did):
        raise DecryptionFailed()
    return _open_boxed(envelope, recipient)


def drop_to(payload: dict, recipient_did: str, recipient_exchange_key: bytes) -> dict:
    """Sealed to a recipient naming NOBODY as the sender.

    Same forward secrecy and confidentiality as a signed envelope; what is
    missing is the sender field, because the phone learns who sent a command
    from the command's own signature against the grant, not from the transport.
    """
    ephemeral = X25519PrivateKey.generate()
    shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(recipient_exchange_key))
    nonce = os.urandom(24)
    boxed = xchacha20poly1305_encrypt(shared, nonce, compact_json(payload).encode("utf-8"))
    return {
        "recipient_did": recipient_did,
        "epk": b64url(ephemeral.public_key().public_bytes_raw()),
        "nonce": b64url(nonce),
        "ciphertext": b64url(boxed[:-16]),
        "mac": b64url(boxed[-16:]),
    }


def _open_boxed(envelope: dict, recipient: PodKeys) -> dict:
    try:
        shared = recipient.shared_secret(unb64url(envelope["epk"]))
        opened = xchacha20poly1305_decrypt(
            shared,
            unb64url(envelope["nonce"]),
            unb64url(envelope["ciphertext"]) + unb64url(envelope["mac"]),
        )
        decoded = json.loads(opened.decode("utf-8"))
    except Exception:
        raise DecryptionFailed()
    if not isinstance(decoded, dict):
        raise DecryptionFailed()
    return decoded


class PeerSession:
    """The cipher protecting one connection after its handshake.

    The X25519 agreement is expanded once per connection with the authenticated
    handshake nonce, not once per frame. Binding the key to that fresh nonce
    also means a frame captured from one connection cannot be replayed into the
    next connection between the same two long-term keys.
    """

    def __init__(self, secret: bytes) -> None:
        self._secret = secret

    @staticmethod
    def derive(own: PodKeys, peer_exchange_key_b64: Any, handshake_nonce: str) -> "PeerSession | None":
        raw = decode_sealed_address(peer_exchange_key_b64)
        if raw is None or not handshake_nonce:
            return None
        try:
            shared = own.shared_secret(raw)
        except Exception:
            return None
        return PeerSession(
            hkdf_sha256(
                shared,
                handshake_nonce.encode("utf-8"),
                f"{PROTOCOL_VERSION}|peer-session".encode("utf-8"),
            )
        )

    def seal(self, frame: bytes) -> bytes:
        nonce = os.urandom(24)
        boxed = xchacha20poly1305_encrypt(self._secret, nonce, frame)
        # nonce ‖ mac ‖ ciphertext — fixed-width prefixes, so the reader never
        # has to trust a length the sender supplied.
        return nonce + boxed[-16:] + boxed[:-16]

    def open(self, body: bytes) -> bytes | None:
        if len(body) < 40:
            return None
        try:
            return xchacha20poly1305_decrypt(self._secret, body[:24], body[40:] + body[24:40])
        except Exception:
            return None


def exchange_key_binding(nonce: str, exchange_key: str) -> bytes:
    """The exact bytes a peer signs to bind its exchange key to one hello."""
    return f"mds-hello-exchange-key|{nonce}|{exchange_key}".encode("utf-8")


# --- framed peer protocol ---------------------------------------------------


def encode_frame(kind: str, headers: dict | None = None, payload: bytes = b"") -> bytes:
    """One framed message.

    A length prefix rather than newline framing: payloads are binary and will
    contain any byte, including whatever delimiter looked convenient.
    """
    header = compact_json({"kind": kind, **(headers or {})}).encode("utf-8")
    return (
        len(header).to_bytes(4, "big") + len(payload).to_bytes(4, "big") + header + payload
    )


class FrameReader:
    """Reads framed messages out of a byte stream.

    TCP delivers a stream, not messages: one write can arrive as three reads.
    The declared lengths come from the other side, so both are bounded before
    anything is buffered for them.
    """

    def __init__(self) -> None:
        self._buffer = bytearray()

    def add(self, chunk: bytes) -> list[tuple[dict, bytes]]:
        self._buffer += chunk
        out: list[tuple[dict, bytes]] = []
        while True:
            if len(self._buffer) < 8:
                return out
            header_length = int.from_bytes(self._buffer[0:4], "big")
            body_length = int.from_bytes(self._buffer[4:8], "big")
            if header_length > MAX_HEADER_BYTES:
                raise Refused(f"the pod announced a header of {header_length} bytes")
            if body_length > MAX_PAYLOAD_BYTES:
                raise Refused(f"the pod announced a payload of {body_length} bytes")
            total = 8 + header_length + body_length
            if len(self._buffer) < total:
                return out
            try:
                header = json.loads(bytes(self._buffer[8 : 8 + header_length]).decode("utf-8"))
            except Exception:
                raise Refused("a frame arrived whose header is not JSON")
            if not isinstance(header, dict):
                raise Refused("a frame arrived whose header is not an object")
            out.append((header, bytes(self._buffer[8 + header_length : total])))
            del self._buffer[:total]

    def decode_single(self, frame: bytes) -> dict:
        """The exact one frame carried by an encrypted session wrapper.

        Retained bytes mean it ended mid-frame; several decoded frames mean it
        smuggled several operations through one wrapper. Both are refused.
        """
        reader = FrameReader()
        messages = reader.add(frame)
        if reader._buffer or len(messages) != 1:
            raise Refused("the pod sent a session body this connector will not unpack")
        return messages[0][0]


class PodLink:
    """One authenticated, encrypted connection to a phone.

    The phone proves its identity and its exchange address before this tool
    offers it anything: a connector that skipped the check would happily enrol
    with whoever answered the port.
    """

    def __init__(self, sock: socket.socket, keys: PodKeys) -> None:
        self._socket = sock
        self._keys = keys
        self._reader = FrameReader()
        self._pending: list[tuple[dict, bytes]] = []
        self.pod_did = ""
        self.pod_exchange_key = b""
        self.protocol: str | None = None
        self.grant_nonce: str | None = None
        self._session: PeerSession | None = None

    @staticmethod
    def connect(host: str, port: int, keys: PodKeys, timeout: float = 20.0) -> "PodLink":
        try:
            sock = socket.create_connection((host, port), timeout=10.0)
        except OSError as error:
            raise Refused(
                f"could not reach the phone at {host}:{port} ({error}).\n"
                "Keep the app open and put both devices on the same private network. "
                "Guest Wi-Fi usually blocks devices from reaching each other."
            )
        sock.settimeout(timeout)
        link = PodLink(sock, keys)
        try:
            link._handshake()
        except BaseException:
            link.close()
            raise
        return link

    @staticmethod
    def connect_to(host: str, port: int, expected_did: str, keys: PodKeys) -> "PodLink":
        """The same, refusing any phone but the one this tool enrolled with.

        A grant belongs to one phone. An address that has been reused on the
        home network would otherwise have this tool offer commands under a
        grant that phone never issued.
        """
        link = PodLink.connect(host, port, keys)
        if link.pod_did != expected_did:
            link.close()
            raise Refused(
                f"the phone at {host}:{port} is not the one this tool is connected to.\n"
                "Check the address, or connect again with a fresh invite."
            )
        return link

    def _handshake(self) -> None:
        nonce = b64url(os.urandom(32))
        own_key = self._keys.encoded_exchange_key
        # Our own key, bound to this nonce. The phone derives the session from
        # it and refuses the connection outright without it: an unbound key on
        # a plaintext socket may already be an on-path attacker's swap.
        self._write(
            encode_frame(
                "hello",
                {
                    "nonce": nonce,
                    "did": self._keys.did,
                    "exchange_key": own_key,
                    "key_proof": self._keys.sign(exchange_key_binding(nonce, own_key)),
                },
            )
        )
        hello = self._next_plain("hello")
        pod_did = hello.get("did")
        proof = hello.get("proof")
        exchange_key = hello.get("exchange_key")
        key_proof = hello.get("key_proof")
        if (
            not isinstance(pod_did, str)
            or not verify_signature(nonce.encode("utf-8"), proof, pod_did)
            or not isinstance(exchange_key, str)
            or not verify_signature(exchange_key_binding(nonce, exchange_key), key_proof, pod_did)
        ):
            raise Refused("the phone did not prove its identity and its address")
        decoded = decode_sealed_address(exchange_key)
        if decoded is None:
            raise Refused("the phone advertised an address this connector cannot seal to")
        session = PeerSession.derive(self._keys, exchange_key, nonce)
        if session is None:
            raise Refused("no encrypted session could be agreed with this phone")
        self.pod_did = pod_did
        self.pod_exchange_key = decoded
        self._session = session
        self.protocol = hello.get("protocol") if isinstance(hello.get("protocol"), str) else None
        got_nonce = hello.get("tool_grant_nonce")
        self.grant_nonce = got_nonce if isinstance(got_nonce, str) else None

    def _write(self, raw: bytes) -> None:
        try:
            self._socket.sendall(raw)
        except OSError as error:
            raise Refused(f"this connector could not send to the phone: {error}")

    def send(self, kind: str, headers: dict | None = None) -> None:
        """Everything after the handshake is sealed. The phone refuses plaintext."""
        assert self._session is not None
        self._write(encode_frame("session", payload=self._session.seal(encode_frame(kind, headers))))

    def _receive(self) -> tuple[dict, bytes]:
        while not self._pending:
            try:
                chunk = self._socket.recv(65536)
            except socket.timeout:
                raise Refused("the phone stopped answering. Is the app still open?")
            except OSError as error:
                raise Refused(f"the connection to the phone failed: {error}")
            if not chunk:
                raise Refused("the phone closed the connection")
            self._pending.extend(self._reader.add(chunk))
        return self._pending.pop(0)

    def _next_plain(self, kind: str) -> dict:
        while True:
            header, _ = self._receive()
            if header.get("kind") == kind:
                return header
            if header.get("kind") == "error":
                raise Refused(self._refusal(header))

    def next(self, kind: str) -> dict:
        """The next frame of this kind, unwrapping the session that carries it."""
        while True:
            header, body = self._receive()
            if header.get("kind") == "session":
                opened = self._session.open(body) if self._session else None
                if opened is None:
                    # A frame this connection cannot open is not one to guess
                    # about — that is how a probe gets an answer it should
                    # never have had.
                    continue
                header = self._reader.decode_single(opened)
            if header.get("kind") == kind:
                return header
            if header.get("kind") == "error":
                raise Refused(self._refusal(header))

    @staticmethod
    def _refusal(header: dict) -> str:
        reason = header.get("reason")
        return "the phone refused this connector" + (
            f": {reason}" if isinstance(reason, str) else ""
        )

    def close(self) -> None:
        try:
            self._socket.close()
        except OSError:
            pass

    def __enter__(self) -> "PodLink":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


# --- the invite -------------------------------------------------------------


class Invite:
    """The opaque text a person hands to a tool to start a connection.

    It carries four things and cannot carry a fifth: where to reach the phone,
    which attempt this is, the challenge to sign, and the protocol being
    spoken. Nothing about an account, a key, a topic or a permission is in it,
    so it stays worthless to everyone who sees it and is not this tool.
    """

    KEYS = {"host", "port", "session", "challenge", "protocol"}

    def __init__(self, host: str, port: int, session_id: str, challenge: str, protocol: str) -> None:
        self.host = host
        self.port = port
        self.session_id = session_id
        self.challenge = challenge
        self.protocol = protocol

    @staticmethod
    def decode(text: Any) -> "Invite | None":
        """Reads an invite, or refuses. Every refusal is the same silence: a
        person who mistyped one character is not told which one."""
        if not isinstance(text, str):
            return None
        trimmed = text.strip()
        if len(trimmed) > INVITE_MAX_ENCODED or not trimmed.startswith(INVITE_SCHEME):
            return None
        try:
            parsed = json.loads(unb64url(trimmed[len(INVITE_SCHEME) :]).decode("utf-8"))
        except Exception:
            return None
        if not isinstance(parsed, dict) or set(parsed) != Invite.KEYS:
            return None
        host, port = parsed["host"], parsed["port"]
        session_id, challenge = parsed["session"], parsed["challenge"]
        protocol = parsed["protocol"]
        if not isinstance(host, str) or not isinstance(session_id, str):
            return None
        if not isinstance(challenge, str) or not isinstance(protocol, str):
            return None
        if not isinstance(port, int) or isinstance(port, bool) or not 0 < port <= 65535:
            return None
        host = host.strip()
        if not host or protocol != PROTOCOL_VERSION:
            return None
        for value in (host, session_id, challenge):
            if not value or len(value) > 128 or _has_unsafe_rune(value):
                return None
        return Invite(host, port, session_id, challenge, protocol)


def _has_unsafe_rune(value: str) -> bool:
    """Hidden and direction-changing text, refused.

    An invite is read by a person and pasted between programs. A host with an
    embedded newline reads as one thing on screen and splits into two
    downstream; a bidi override reads as one host and resolves as another.
    """
    for character in value:
        code = ord(character)
        if code < 0x20 or code == 0x7F or 0x80 <= code <= 0x9F:
            return True
        if code in (0x061C, 0x200E, 0x200F, 0xFEFF):
            return True
        if 0x200B <= code <= 0x200D or 0x202A <= code <= 0x202E or 0x2066 <= code <= 0x2069:
            return True
        if 0x2060 <= code <= 0x2064 or code in (0x00AD, 0x180E):
            return True
    return False


# --- what a connection is bound to ------------------------------------------
#
# Every message below is domain-separated, so a signature minted for one step
# of this ceremony can never be presented as another.


def possession_binding(challenge: str, tool_did: str, label: str, exchange_key: str) -> bytes:
    """The bytes a tool signs to prove it holds the key its DID names.

    The label is inside it on purpose: a proof over the challenge alone would
    vouch for the DID and say nothing about the name rendered beside it on the
    approval screen, so anything carrying the offer could leave the proof
    intact and swap the name the person reads while deciding.
    """
    return f"mds-tool-enrolment|{challenge}|{tool_did}|{label}|{exchange_key}".encode("utf-8")


def grant_connection_transcript(pod_did: str, tool_did: str, nonce: str, request_signature: str) -> bytes:
    """What a tool signs to prove this connection is its own.

    The exact request is inside it. Binding only the nonce would authenticate
    the socket and leave the sealed request interchangeable on it.
    """
    return compact_json(
        {
            "v": PROTOCOL_VERSION,
            "op": "tool_grant_collect",
            "pod": pod_did,
            "tool": tool_did,
            "nonce": nonce,
            "request": request_signature,
        }
    ).encode("utf-8")


def grant_request_transcript(
    session_id: str, challenge: str, tool_did: str, pod_did: str, tool_exchange_key: str
) -> str:
    return f"mds-tool-grant-request|{session_id}|{challenge}|{tool_did}|{pod_did}|{tool_exchange_key}"


def grant_transcript(session_id: str, challenge: str, grant: "ToolGrant") -> str:
    return (
        "mds-tool-grant"
        f"|{session_id}|{challenge}|{grant.grant_id}|{grant.owner_did}|{grant.tool_did}"
        f"|{grant.signature or ''}"
    )


def receipt_transcript(session_id: str, challenge: str, grant: "ToolGrant") -> str:
    return (
        "mds-tool-grant-receipt-transcript"
        f"|{session_id}|{challenge}|{grant.grant_id}|{grant.owner_did}|{grant.tool_did}"
        f"|{grant.signature or ''}"
    )


def receipt_binding(session_id: str, grant_id: str, grant_signature: str) -> bytes:
    return f"mds-tool-grant-receipt|{session_id}|{grant_id}|{grant_signature}".encode("utf-8")


def ack_transcript(command: "ToolCommand") -> str:
    """Bound to the command's own SIGNATURE, not merely its id: an id is chosen
    by the caller and repeats across retries."""
    return f"mds-tool-ack|{command.command_id}|{command.grant_id}|{command.signature}"


# --- the permission the phone grants ----------------------------------------

ACTIONS = ("readEntries", "readTopicStructure", "appendEntry", "readWatches")


class ToolGrant:
    """The owner-signed capability. Read, never minted here.

    The signature covers the fields a tool could otherwise widen for itself,
    and it is checked against the OWNER's key — a grant that verified against
    the tool would be the tool authorising itself.
    """

    def __init__(self, raw: dict) -> None:
        self.raw = raw
        self.grant_id = raw["grant_id"]
        self.tool_did = raw["tool_did"]
        self.owner_did = raw["owner_did"]
        self.actions = list(raw["actions"])
        self.scope = raw["scope"]
        self.quota = raw["quota"]
        self.signature = raw.get("signature")
        self.protected = raw.get("protected")
        self.state = raw.get("state")
        self.issued_at = raw.get("issued_at")
        self.expires_at = raw.get("expires_at")

    @staticmethod
    def parse(raw: Any) -> "ToolGrant | None":
        """Total, exact and fail-closed for every slot. An unreadable grant is
        refused rather than parsed into something a later door might trust."""
        if not isinstance(raw, dict):
            return None
        allowed = {
            "grant_id", "tool_did", "owner_did", "actions", "scope", "quota",
            "issued_at", "expires_at", "state", "protected", "signature",
        }
        if set(raw) - allowed:
            return None
        for key in ("grant_id", "tool_did", "owner_did"):
            if not isinstance(raw.get(key), str) or not raw[key]:
                return None
        if public_key_from_did(raw["tool_did"]) is None:
            return None
        if public_key_from_did(raw["owner_did"]) is None:
            return None
        if parse_wire_time(raw.get("issued_at")) is None:
            return None
        actions = raw.get("actions")
        if not isinstance(actions, list) or not actions or len(actions) > len(ACTIONS):
            return None
        if len(set(actions)) != len(actions) or any(a not in ACTIONS for a in actions):
            return None
        scope, quota = raw.get("scope"), raw.get("quota")
        if not isinstance(scope, dict) or not isinstance(quota, dict):
            return None
        topics = scope.get("topics")
        if not isinstance(topics, list) or not topics:
            return None
        for topic in topics:
            if not isinstance(topic, dict) or not isinstance(topic.get("space_id"), str):
                return None
        if not isinstance(quota.get("max_commands"), int):
            return None
        if not isinstance(quota.get("window_seconds"), int):
            return None
        if ("protected" in raw) != ("signature" in raw):
            return None
        if "expires_at" in raw and parse_wire_time(raw["expires_at"]) is None:
            return None
        return ToolGrant(raw)

    @property
    def signed_claim(self) -> dict:
        """Exactly what the owner signs. Excludes the state and the watermark:
        pausing is a local decision that must not require a new signature."""
        claim = {
            "grant_id": self.grant_id,
            "tool_did": self.tool_did,
            "owner_did": self.owner_did,
            "actions": sorted(self.actions),
            "scope": self.scope,
            "quota": self.quota,
            "issued_at": self.issued_at,
        }
        if self.expires_at is not None:
            claim["expires_at"] = self.expires_at
        return claim

    def has_valid_signature(self) -> bool:
        """The carried bytes AND the readable claim.

        Verifying re-derived bytes would require every language to reproduce
        the app's encoding; verifying carried bytes without comparing the claim
        would let a grant display fields nobody signed.
        """
        if not self.protected or not self.signature:
            return False
        try:
            carried = json.loads(unb64url(self.protected).decode("utf-8"))
        except Exception:
            return False
        if not isinstance(carried, dict):
            return False
        if compact_json(canonical(carried)) != compact_json(canonical(self.signed_claim)):
            return False
        return verify_signature(unb64url(self.protected), self.signature, self.owner_did)

    @property
    def topics(self) -> list[str]:
        return [topic["space_id"] for topic in self.scope["topics"]]

    def fields_for(self, space_id: str) -> list[str] | None:
        for topic in self.scope["topics"]:
            if topic["space_id"] == space_id:
                keys = topic.get("field_keys")
                return list(keys) if isinstance(keys, list) else None
        return None

    def describe(self) -> str:
        lines = ["Granted: " + ", ".join(sorted(self.actions))]
        for topic in self.scope["topics"]:
            keys = topic.get("field_keys")
            which = ", ".join(keys) if isinstance(keys, list) and keys else "every field"
            lines.append(f"  topic {topic['space_id']}: {which}")
        window = self.quota["window_seconds"]
        lines.append(f"  rate: up to {self.quota['max_commands']} every {window}s")
        lines.append(f"  ends: {self.expires_at or 'no end date'}")
        return "\n".join(lines)


class ToolCommand:
    """One command, carrying its own place in the grant's sequence."""

    def __init__(
        self,
        command_id: str,
        grant_id: str,
        sequence: int,
        issued_at: _dt.datetime,
        space_id: str,
        values: dict,
        occurred_at: _dt.datetime | None,
    ) -> None:
        self.command_id = command_id
        self.grant_id = grant_id
        self.sequence = sequence
        self.issued_at = issued_at
        self.space_id = space_id
        self.values = values
        self.occurred_at = occurred_at
        self.signature = ""
        self.protected = b""

    @property
    def payload(self) -> dict:
        payload: dict[str, Any] = {"space_id": self.space_id, "values": self.values}
        if self.occurred_at is not None:
            payload["occurred_at"] = wire_time(self.occurred_at)
        return payload

    @property
    def signed_claim(self) -> dict:
        return {
            "command_id": self.command_id,
            "grant_id": self.grant_id,
            "action": "appendEntry",
            "sequence": self.sequence,
            "issued_at": wire_time(self.issued_at),
            "payload": self.payload,
        }

    def sign(self, keys: PodKeys) -> "ToolCommand":
        self.protected = canonical_bytes(self.signed_claim)
        self.signature = keys.sign(self.protected)
        return self

    def to_json(self) -> dict:
        return {
            **self.signed_claim,
            "protected": b64url(self.protected),
            "signature": self.signature,
        }


class CommandAck:
    """What the phone answered. `alreadyExecuted` is not an error: at-most-once
    execution must not leave a caller guessing whether a timed-out command
    acted."""

    def __init__(self, command_id: str, outcome: str, activity_id: str | None) -> None:
        self.command_id = command_id
        self.outcome = outcome
        self.activity_id = activity_id

    @staticmethod
    def parse(raw: Any) -> "CommandAck | None":
        if not isinstance(raw, dict):
            return None
        if set(raw) - {"command_id", "outcome", "activity_id", "entries"}:
            return None
        command_id, outcome = raw.get("command_id"), raw.get("outcome")
        if not isinstance(command_id, str) or not isinstance(outcome, str) or not outcome:
            return None
        activity_id = raw.get("activity_id")
        if activity_id is not None and not isinstance(activity_id, str):
            return None
        if outcome in ("executed", "alreadyExecuted") and not activity_id:
            return None
        return CommandAck(command_id, outcome, activity_id)


# --- the two exchanges that connect a tool ----------------------------------


def seal_grant_request(
    session_id: str,
    challenge: str,
    keys: PodKeys,
    pod_did: str,
    pod_exchange_key: bytes,
) -> dict:
    """The tool's sealed, tool-signed request for the reviewed permission.

    The payload names only the session; the transcript is what makes even that
    unforgeable, because it binds this tool, this phone, this attempt and the
    exact address the possession proof vouched for.
    """
    return seal_envelope(
        {
            "session_id": session_id,
            "transcript": grant_request_transcript(
                session_id, challenge, keys.did, pod_did, keys.encoded_exchange_key
            ),
        },
        keys,
        pod_did,
        pod_exchange_key,
    )


def open_sealed_grant(
    sealed: Any, session_id: str, challenge: str, pod_did: str, keys: PodKeys
) -> ToolGrant:
    """Opens and AUTHENTICATES a delivered permission.

    [pod_did] is the identity the handshake proved, never the sender field of
    the envelope taken at its word — that field is what is being checked, so
    trusting it would make the check circular.
    """
    if not isinstance(sealed, dict):
        raise Refused("the phone's answer carried nothing this connector could read")
    if sealed.get("sender_did") != pod_did:
        # The tool's address is public; a carrier can produce a perfectly valid
        # envelope for it. WHO sealed it is the question, not whether it is sealed.
        raise Refused("the permission was sealed by somebody other than this phone")
    opened = open_envelope(sealed, keys)
    grant = ToolGrant.parse(opened.get("grant"))
    if grant is None:
        raise Refused("the delivered permission could not be read")
    if grant.tool_did != keys.did:
        raise Refused("the delivered permission is for a different tool")
    if opened.get("transcript") != grant_transcript(session_id, challenge, grant):
        raise Refused("the delivered permission belongs to a different review")
    if grant.owner_did != pod_did:
        raise Refused("the phone that sealed this permission did not sign it")
    if not grant.has_valid_signature():
        raise Refused("the delivered permission is not signed by the account that granted it")
    return grant


def seal_receipt(
    grant: ToolGrant, session_id: str, challenge: str, keys: PodKeys, pod_did: str, pod_exchange_key: bytes
) -> dict:
    """The tool's signed confirmation that it received the permission.

    Without it, a lost delivery would leave the owner looking at a tool that
    can never act and that they never actually connected.
    """
    if not grant.signature:
        raise Refused("there is no signed permission to acknowledge")
    receipt = {
        "session_id": session_id,
        "grant_id": grant.grant_id,
        "tool_did": keys.did,
        "signature": keys.sign(receipt_binding(session_id, grant.grant_id, grant.signature)),
    }
    return seal_envelope(
        {"receipt": receipt, "transcript": receipt_transcript(session_id, challenge, grant)},
        keys,
        pod_did,
        pod_exchange_key,
    )


def open_sealed_ack(sealed: Any, command: ToolCommand, pod_did: str, keys: PodKeys) -> CommandAck:
    """Opens and AUTHENTICATES a sealed acknowledgement.

    Three things must hold: it opens for this tool, it was SIGNED by the phone
    the handshake proved, and its transcript names the exact request being
    answered.
    """
    if not isinstance(sealed, dict) or sealed.get("sender_did") != pod_did:
        raise Refused("the phone's acknowledgement was not signed by the phone")
    opened = open_envelope(sealed, keys)
    ack = CommandAck.parse(opened.get("ack"))
    if ack is None or ack.command_id != command.command_id:
        raise Refused("the phone acknowledged something other than what was sent")
    if opened.get("transcript") != ack_transcript(command):
        raise Refused("the phone's acknowledgement answers a different request")
    return ack


def connect_tool(
    keys: PodKeys, invite: Invite, label: str, required_topic: str, say=print
) -> tuple[ToolGrant, str, int]:
    """Completes the connection a person started by revealing an invite.

    The offer is proved, the sealed permission is opened and checked, and the
    receipt is sealed back — the phone installs nothing until this tool has
    acknowledged the exact permission the person reviewed.
    """
    with PodLink.connect(invite.host, invite.port, keys) as link:
        if link.protocol != invite.protocol:
            raise Refused(
                "the app on that phone speaks a version this invite was not made for.\n"
                "Update the app, then copy a fresh invite."
            )
        exchange_key = keys.encoded_exchange_key
        link.send(
            "offerToolEnrolment",
            {
                "tool_did": keys.did,
                "label": label,
                "challenge": invite.challenge,
                "exchange_key": exchange_key,
                "signature": keys.sign(
                    possession_binding(invite.challenge, keys.did, label, exchange_key)
                ),
            },
        )
        if link.next("toolEnrolmentPending").get("reviewing") is not True:
            raise Refused(
                "the phone did not put this tool up for review.\n"
                "Invites are short-lived and one connection at a time is allowed — "
                "copy a fresh one and try again."
            )
        say(f'Offered as "{label}". Approve it on the phone.')

        request = seal_grant_request(
            invite.session_id, invite.challenge, keys, link.pod_did, link.pod_exchange_key
        )
        grant: ToolGrant | None = None
        deadline = time.monotonic() + 300
        while grant is None and time.monotonic() < deadline:
            nonce = link.grant_nonce
            if nonce is None:
                raise Refused("the phone stopped minting connection nonces")
            link.send(
                "wantToolGrant",
                {
                    "tool_did": keys.did,
                    "proof": keys.sign(
                        grant_connection_transcript(
                            link.pod_did, keys.did, nonce, request["signature"]
                        )
                    ),
                    "sealed_request": request,
                },
            )
            reply = link.next("toolGrant")
            next_nonce = reply.get("tool_grant_nonce")
            link.grant_nonce = next_nonce if isinstance(next_nonce, str) else None
            sealed = reply.get("sealed_grant")
            if sealed is None:
                time.sleep(2)
                continue
            grant = open_sealed_grant(
                sealed, invite.session_id, invite.challenge, link.pod_did, keys
            )
        if grant is None:
            raise Refused("nobody finished the review in time. Start again with a fresh invite.")

        # What the person actually allowed, said out loud before anything uses it.
        say(grant.describe())
        if "appendEntry" not in grant.actions:
            raise Refused(
                "this permission cannot add entries, so this connector has nothing to do "
                "with it. Approve 'Add entries' when you review it."
            )
        # **Checked here, before the receipt.** The phone installs nothing until
        # the receipt goes back, so refusing now leaves the person with no
        # half-made connected tool that would refuse every reading.
        if required_topic not in grant.topics:
            raise Refused(
                f"this permission does not cover the topic you passed as --topic "
                f"({required_topic}).\nIt covers: {', '.join(grant.topics)}"
            )

        receipt = seal_receipt(
            grant, invite.session_id, invite.challenge, keys, link.pod_did, link.pod_exchange_key
        )
        nonce = link.grant_nonce
        if nonce is None:
            raise Refused("the phone stopped minting connection nonces")
        link.send(
            "toolGrantReceipt",
            {
                "tool_did": keys.did,
                "proof": keys.sign(
                    grant_connection_transcript(
                        link.pod_did, keys.did, nonce, receipt["signature"]
                    )
                ),
                "sealed_receipt": receipt,
            },
        )
        if link.next("toolGrantReceipt").get("installed") is not True:
            raise Refused("the phone did not install the permission it handed over")
        return grant, link.pod_did, invite.port


def send_append(link: PodLink, keys: PodKeys, command: ToolCommand) -> CommandAck:
    """Sends one sealed entry and says what the phone did with it.

    **Sealed, always.** A plaintext command from anywhere but the phone itself
    is refused before a permission is even looked up: verifying a command
    proves who wrote it and says nothing about who can read the answer.
    """
    link.send(
        "toolCommand",
        {
            "sealed_command": drop_to(
                {"command": command.to_json()}, link.pod_did, link.pod_exchange_key
            )
        },
    )
    reply = link.next("toolAck")
    sealed = reply.get("sealed_ack")
    if not isinstance(sealed, dict):
        # Noise on the wire, not a decision by the owner. Raised so the round
        # fails and the next one carries the same reading again.
        raise Refused("the phone's acknowledgement carried no sealed answer")
    return open_sealed_ack(sealed, command, link.pod_did, keys)


# What to do about one acknowledgement.
CARRIED, ALREADY_THERE, RETRY, WAIT_LONGER, STOP_ROUND, STOP = (
    "carried", "already-there", "retry", "wait", "stop-round", "stop",
)

_DISPOSITIONS = {
    "executed": CARRIED,
    "alreadyExecuted": ALREADY_THERE,
    # This exact command cannot land, so issue a new one.
    "replayedSequence": RETRY,
    "staleCommand": RETRY,
    # Nothing more this round, but the next one may well work.
    "quotaExhausted": WAIT_LONGER,
    "grantPaused": WAIT_LONGER,
    # None of these change by waiting.
    "unknownGrant": STOP,
    "grantRevoked": STOP,
    "grantExpired": STOP,
    "ownerChanged": STOP,
    "badToolSignature": STOP,
    "outOfScope": STOP,
    "actionNotGranted": STOP,
    "actionNotSupported": STOP,
}

_PLAIN_OUTCOMES = {
    "grantPaused": "the tool is paused on the phone",
    "quotaExhausted": "the rate you allowed is used up for now",
    "grantRevoked": "the tool was disconnected on the phone",
    "grantExpired": "the end date you set has passed",
    "unknownGrant": "the phone no longer knows this tool",
    "ownerChanged": "the phone is signed in as a different account",
    "outOfScope": "this topic or field is outside what you allowed",
    "actionNotGranted": "adding entries was not among the things you allowed",
    "actionNotSupported": "this version of the app cannot carry that out",
    "badToolSignature": "the phone could not verify this tool's signature",
}


def disposition_for(outcome: str) -> str:
    return _DISPOSITIONS.get(outcome, STOP_ROUND)


def plainly(outcome: str | None) -> str:
    if outcome is None:
        return "the phone asked us to wait"
    return _PLAIN_OUTCOMES.get(outcome, outcome)


# --- the machine side: a profile is data, not code ---------------------------
#
# A profile says where a machine's records live, how to sign in, and how one
# record becomes one entry. The mapping vocabulary is a CLOSED set of rules —
# text, number, duration, time, join, count, constant — for the same reason the
# app's helper canvas has a closed set of boxes: a mapping that can express
# anything is a scripting language with a worse editor, and nobody can review
# it. A profile naming a rule this build does not know is refused, not guessed.

from decimal import Decimal, ROUND_HALF_UP  # noqa: E402  (kept beside its use)


def read_path(record: Any, path: str) -> Any:
    """A dotted path into a decoded record.

    Maps only, and one level of list indexing by number. `.` is this record,
    because some machines answer with a document that IS the value.
    """
    if not path or path == ".":
        return record
    current = record
    for segment in path.split("."):
        if isinstance(current, dict) and segment in current:
            current = current[segment]
            continue
        if isinstance(current, list) and segment.lstrip("-").isdigit():
            index = int(segment)
            if 0 <= index < len(current):
                current = current[index]
                continue
        return None
    return current


def _rounded(value: float, decimals: int | None) -> float:
    if decimals is None:
        return value
    quantum = Decimal(1).scaleb(-decimals)
    return float(Decimal(value).quantize(quantum, rounding=ROUND_HALF_UP))


def believable_instant(at: _dt.datetime) -> bool:
    """A wildly out-of-range instant is a unit mistake, not a reading.

    Epoch milliseconds read as seconds land tens of thousands of years out, and
    writing that into somebody's history as though the machine had said it is
    worse than saying nothing.
    """
    return 1990 <= at.year <= 2200


def _instant_from_count(counted: float, unit: str) -> _dt.datetime | None:
    millis = counted if unit == "ms" else counted * 1000
    if abs(millis) > 1e15:
        return None
    try:
        return _dt.datetime.fromtimestamp(round(millis) / 1000, _dt.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _try_date(text: str) -> _dt.datetime | None:
    candidate = text.strip()
    if not candidate:
        return None
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        parsed = _dt.datetime.fromisoformat(candidate)
    except ValueError:
        if len(candidate) == 8 and candidate.isdigit():
            try:
                parsed = _dt.datetime.strptime(candidate, "%Y%m%d")
            except ValueError:
                return None
        else:
            return None
    # A zoneless string means local time, the same reading the app takes.
    if parsed.tzinfo is None:
        parsed = parsed.astimezone()
    return parsed.astimezone(_dt.timezone.utc)


def instant_at(raw: Any, unit: str = "s") -> _dt.datetime | None:
    """The instant a machine means by [raw]: an epoch count, or a date.

    Which reading wins is decided by which one is believable, not by trying the
    date first: ten digits are a perfectly good epoch and a nonsense year.
    """
    if isinstance(raw, bool):
        return None
    if isinstance(raw, (int, float)):
        return _instant_from_count(float(raw), unit)
    if isinstance(raw, str):
        as_date = _try_date(raw)
        try:
            counted = float(raw)
            as_count = _instant_from_count(counted, unit) if counted == counted else None
        except ValueError:
            as_count = None
        if as_date is not None and (believable_instant(as_date) or as_count is None):
            return as_date
        return as_count
    return None


class ValueRule:
    """How one entry field is produced from one record."""

    def __init__(self, kind: str, spec: dict) -> None:
        self.kind = kind
        self.spec = spec

    def read(self, record: Any) -> Any:
        """The value, or None to leave the field out entirely.

        **Absent is not zero**: an omitted number is a measurement nobody took,
        and writing 0 would be a claim the machine never made.
        """
        kind, spec = self.kind, self.spec
        if kind == "constant":
            return spec["value"]
        if kind == "duration":
            start = _seconds(read_path(record, spec["from"]))
            end = _seconds(read_path(record, spec["to"]))
            # An open event has no duration. Reporting 0 would invent the end
            # of something still running.
            if start is None or end is None:
                return None
            return _rounded(end - start, spec["decimals"])
        candidates = [spec["path"]] + ([spec["or"]] if spec.get("or") else [])
        if kind == "text":
            for candidate in candidates:
                value = read_path(record, candidate)
                if isinstance(value, str) and value.strip():
                    return value.strip()
                if isinstance(value, bool):
                    return "true" if value else "false"
                if isinstance(value, (int, float)):
                    return _dart_number_text(value)
            return None
        if kind == "number":
            for candidate in candidates:
                raw = read_path(record, candidate)
                value = None
                if isinstance(raw, bool):
                    value = None
                elif isinstance(raw, (int, float)):
                    value = float(raw)
                elif isinstance(raw, str):
                    try:
                        value = float(raw)
                    except ValueError:
                        value = None
                # Non-finite is not a reading. A machine reporting Infinity has
                # told us its sensor failed, not that the value is enormous.
                if value is None or value != value or value in (float("inf"), float("-inf")):
                    continue
                return _rounded(value * spec["factor"], spec["decimals"])
            return None
        if kind == "time":
            for candidate in candidates:
                at = instant_at(read_path(record, candidate), unit=spec["unit"])
                if at is not None and believable_instant(at):
                    return wire_time(at)
            return None
        if kind == "join":
            raw = read_path(record, spec["path"])
            if not isinstance(raw, list):
                return None
            parts = [item.strip() for item in raw if isinstance(item, str) and item.strip()]
            if not parts:
                return None
            # Sorted by default: machines report set-like values in arrival
            # order, so one situation arrives spelled two ways and every later
            # comparison breaks.
            if spec["sort"]:
                parts.sort()
            return spec["separator"].join(parts)
        if kind == "count":
            raw = read_path(record, spec["path"])
            if isinstance(raw, (list, dict)):
                return len(raw)
            return None
        return None

    @staticmethod
    def parse(raw: Any) -> "ValueRule | None":
        # A bare string is the common case: "read this path as text".
        if isinstance(raw, str):
            return ValueRule("text", {"path": raw, "or": None})
        if not isinstance(raw, dict):
            return None
        kind = raw.get("kind")
        path = raw.get("path") if isinstance(raw.get("path"), str) and raw.get("path") else None
        fallback = raw.get("or") if isinstance(raw.get("or"), str) and raw.get("or") else None
        if kind == "constant":
            return ValueRule("constant", {"value": raw.get("value")})
        if kind == "duration":
            start, end = raw.get("from"), raw.get("to")
            if not isinstance(start, str) or not start or not isinstance(end, str) or not end:
                return None
            decimals = raw.get("decimals")
            return ValueRule(
                "duration",
                {
                    "from": start,
                    "to": end,
                    "decimals": decimals if isinstance(decimals, int) else 1,
                },
            )
        if path is None:
            return None
        if kind == "time":
            unit = raw.get("unit") if isinstance(raw.get("unit"), str) and raw.get("unit") else "s"
            if unit not in ("s", "ms"):
                return None
            return ValueRule("time", {"path": path, "or": fallback, "unit": unit})
        if kind == "text":
            return ValueRule("text", {"path": path, "or": fallback})
        if kind == "number":
            decimals = raw.get("decimals")
            factor = raw.get("factor")
            return ValueRule(
                "number",
                {
                    "path": path,
                    "or": fallback,
                    "decimals": decimals if isinstance(decimals, int) else None,
                    "factor": float(factor) if isinstance(factor, (int, float)) else 1.0,
                },
            )
        if kind == "join":
            separator = raw.get("separator")
            return ValueRule(
                "join",
                {
                    "path": path,
                    "separator": separator if isinstance(separator, str) and separator else ", ",
                    "sort": raw.get("sort") is not False,
                },
            )
        if kind == "count":
            return ValueRule("count", {"path": path})
        # A rule this build has never heard of. Refused rather than skipped: a
        # profile that silently loses a field writes entries that look complete
        # and are not.
        return None


def _dart_number_text(value: int | float) -> str:
    """A number as the app would write it, so a text field reads the same."""
    if isinstance(value, int):
        return str(value)
    if value == int(value) and abs(value) < 1e21:
        return f"{int(value)}.0"
    return repr(value)


def _seconds(raw: Any) -> float | None:
    at = instant_at(raw)
    return None if at is None else at.timestamp()


_TOP_LEVEL_KEYS = {
    "name", "source", "mapping", "topic_fields", "rollup",
    "topic_name", "topic_slug", "root_type",
}
_SOURCE_KEYS = {
    "kind", "path", "url_key", "auth", "query", "headers", "records_path",
    "records_mode", "id_path", "time_path", "limit_param", "since_param",
    "port", "topic", "require", "key_field",
}
_AUTH_KEYS = {
    "kind", "login_path", "user_field", "password_field", "header",
    "user_key", "password_key", "token_key",
}
_ROLLUP_KEYS = {"every_seconds", "group_by", "count_into", "aggregate"}
_ROLLUP_KINDS = ("sum", "max", "min", "mean", "first", "last")


def _unknown_key_refusal(raw: Any) -> str | None:
    """The first key this build does not read, or nothing.

    A key beginning with `_` is left alone: JSON has no comments, and a profile
    is a document somebody maintains. `"_why"` is a note, not a mistake.
    """

    def flat(value: str) -> str:
        return re.sub(r"[_-]", "", value.lower())

    def check(where: str, mapping: Any, known: set[str]) -> str | None:
        if not isinstance(mapping, dict):
            return None
        for key in map(str, mapping):
            if key.startswith("_") or key in known:
                continue
            near = [c for c in sorted(known) if flat(c) == flat(key) or flat(c).startswith(flat(key))]
            hint = f'Did you mean "{near[0]}"?' if near else f"It knows: {', '.join(sorted(known))}."
            return f'{where} names "{key}", which this connector does not read. {hint}'
        return None

    if not isinstance(raw, dict):
        return None
    source = raw.get("source")
    return (
        check("a profile", raw, _TOP_LEVEL_KEYS)
        or check("a source", source, _SOURCE_KEYS)
        or check("a sign-in", source.get("auth") if isinstance(source, dict) else None, _AUTH_KEYS)
        or check("a rollup", raw.get("rollup"), _ROLLUP_KEYS)
    )


class Rollup:
    """How a profile summarises a burst of records into one entry.

    A rate you allow is a ceiling, not an obstacle. Four cameras can emit
    detections far faster than anyone makes diary entries; rolling up is how
    this connector chooses among readings rather than being cut off part-way
    through them.
    """

    def __init__(self, every_seconds: int, group_by: list[str], count_into: str | None, aggregate: dict) -> None:
        self.every_seconds = every_seconds
        self.group_by = group_by
        self.count_into = count_into
        self.aggregate = aggregate

    @staticmethod
    def parse(raw: Any, declared: set[str]) -> tuple["Rollup | None", str | None]:
        if raw is None:
            return None, None
        if not isinstance(raw, dict):
            return None, "a rollup must be a JSON object"
        every = raw.get("every_seconds")
        if not isinstance(every, int) or isinstance(every, bool) or every <= 0:
            return None, "a rollup needs a positive every_seconds"
        group_by = [k for k in raw.get("group_by", []) if isinstance(k, str)] if isinstance(raw.get("group_by"), list) else []
        count_into = raw.get("count_into")
        if count_into is not None and not isinstance(count_into, str):
            return None, "count_into must name an entry field"
        aggregate: dict[str, str] = {}
        if isinstance(raw.get("aggregate"), dict):
            for key, kind in raw["aggregate"].items():
                if not isinstance(kind, str) or kind not in _ROLLUP_KINDS:
                    return None, (
                        f'the rollup combines "{key}" with "{kind}", which this connector does '
                        f"not know. It knows: {', '.join(_ROLLUP_KINDS)}"
                    )
                aggregate[str(key)] = kind
        # Every field a rollup writes must be one the topic declares: the phone
        # refuses an entry naming a field the topic has never had, and it
        # refuses the whole entry, not the field.
        for key in [*group_by, *( [count_into] if isinstance(count_into, str) else [] ), *aggregate]:
            if key not in declared:
                return None, f'the rollup writes "{key}", which the profile\'s topic does not declare'
        if not group_by and count_into is None and not aggregate:
            return None, "a rollup that groups by nothing and keeps nothing has nothing to say"
        return Rollup(every, group_by, count_into if isinstance(count_into, str) else None, aggregate), None


class MachineProfile:
    """One machine, described entirely as data."""

    def __init__(self, raw: dict, mapping: dict, topic_fields: list, rollup: "Rollup | None") -> None:
        source = raw.get("source", {})
        auth = source.get("auth") if isinstance(source.get("auth"), dict) else {}
        self.name = raw["name"]
        self.mapping = mapping
        self.topic_fields = topic_fields
        self.rollup = rollup
        self.topic_name = _text(raw.get("topic_name"), "Machine readings")
        self.topic_slug = _text(raw.get("topic_slug"), "machine-readings")
        self.root_type = _text(raw.get("root_type"), "Reading")
        self.source_kind = _text(source.get("kind"), "http")
        self.url_key = _text(source.get("url_key"), "link")
        self.request_path = _text(source.get("path"), "")
        self.records_path = _text(source.get("records_path"), "")
        self.records_mode = (
            source.get("records_mode")
            if source.get("records_mode") in ("values", "one")
            else "list"
        )
        self.id_path = source.get("id_path") if isinstance(source.get("id_path"), str) else None
        self.time_path = source.get("time_path") if isinstance(source.get("time_path"), str) else None
        self.limit_param = source.get("limit_param") if isinstance(source.get("limit_param"), str) else None
        self.since_param = source.get("since_param") if isinstance(source.get("since_param"), str) else None
        self.query = {str(k): str(v) for k, v in (source.get("query") or {}).items()}
        self.headers = {str(k): str(v) for k, v in (source.get("headers") or {}).items()}
        self.require = dict(source.get("require") or {})
        self.key_field = _text(source.get("key_field"), "_key")
        self.broker_port = source["port"] if isinstance(source.get("port"), int) else 1883
        self.broker_topic = source.get("topic") if isinstance(source.get("topic"), str) else None
        self.auth_kind = _text(auth.get("kind"), "none")
        self.login_path = auth.get("login_path") if isinstance(auth.get("login_path"), str) else None
        self.user_field = _text(auth.get("user_field"), "user")
        self.password_field = _text(auth.get("password_field"), "password")
        self.auth_header = auth.get("header") if isinstance(auth.get("header"), str) else None
        self.user_key = _text(auth.get("user_key"), "user")
        self.password_key = _text(auth.get("password_key"), "password")
        self.token_key = _text(auth.get("token_key"), "token")

    @property
    def topic_template(self) -> dict:
        """The topic a person should create for this machine. A tool may not
        invent a topic; this is what to make."""
        return {
            "slug": self.topic_slug,
            "name": self.topic_name,
            "root_type": self.root_type,
            "fields": self.topic_fields,
        }

    @staticmethod
    def parse(raw: Any) -> tuple["MachineProfile | None", str | None]:
        """Parses a profile, refusing anything it cannot carry out faithfully."""
        if not isinstance(raw, dict):
            return None, "a profile must be a JSON object"
        if not isinstance(raw.get("name"), str) or not isinstance(raw.get("source"), dict):
            return None, "a profile needs a name and a source"
        refusal = _unknown_key_refusal(raw)
        if refusal:
            return None, refusal
        source = raw["source"]
        request_path = source.get("path") if isinstance(source.get("path"), str) else ""
        if not request_path and source.get("kind") != "mqtt":
            return None, "the source needs a request path"
        mapping_raw = raw.get("mapping")
        if not isinstance(mapping_raw, dict) or not mapping_raw:
            return None, "a profile needs a mapping of at least one entry field"
        mapping: dict[str, ValueRule] = {}
        for key, spec in mapping_raw.items():
            rule = ValueRule.parse(spec)
            if rule is None:
                return None, f'the mapping for "{key}" names a rule this connector does not know'
            mapping[str(key)] = rule
        fields_raw = raw.get("topic_fields")
        topic_fields = [f for f in fields_raw if isinstance(f, dict)] if isinstance(fields_raw, list) else []
        if not topic_fields:
            return None, "a profile must say which topic fields it writes"
        declared = {f["key"] for f in topic_fields if isinstance(f.get("key"), str)}
        for key in mapping:
            if key not in declared:
                return None, f'the mapping writes "{key}", which the profile\'s topic does not declare'
        rollup, rollup_refusal = Rollup.parse(raw.get("rollup"), declared)
        if rollup_refusal:
            return None, rollup_refusal
        kind = source.get("kind") if isinstance(source.get("kind"), str) else "http"
        if kind not in ("http", "mqtt"):
            return None, f'this connector does not know the source kind "{kind}". It knows: http, mqtt'
        if kind == "mqtt" and not (isinstance(source.get("topic"), str) and source["topic"]):
            return None, "an mqtt source needs the topic to subscribe to"
        return MachineProfile(raw, mapping, topic_fields, rollup), None


def _text(value: Any, fallback: str) -> str:
    return value if isinstance(value, str) and value else fallback


def entry_values(profile: MachineProfile, record: Any) -> dict:
    """One record as entry values. Absent facts are omitted, never defaulted."""
    values = {}
    for key, rule in profile.mapping.items():
        value = rule.read(record)
        if value is not None:
            values[key] = value
    return values


def select_records(profile: MachineProfile, decoded: Any) -> list:
    """The records inside a reply, per the profile's selector."""
    # Checked against the WHOLE document, before the records are located: what
    # decides whether a camera's announcement is worth carrying ("this event
    # has ended") usually sits beside the record rather than inside it.
    for path, expected in profile.require.items():
        if read_path(decoded, path) != expected:
            return []
    located = read_path(decoded, profile.records_path)
    if profile.records_mode == "values" and isinstance(located, dict):
        # **The key travels with the record.** Several machines answer with an
        # object keyed by the thing's own name, and the value does not repeat
        # it — dropping the key throws away the only identity those records
        # have. The machine's own field wins if it uses this name.
        out = []
        for key, value in located.items():
            if isinstance(value, dict):
                out.append({profile.key_field: str(key), **value})
            else:
                out.append(value)
        return out
    # One announcement is one record. A broker delivers a document per event.
    if profile.records_mode == "one":
        return [] if located is None else [located]
    return located if isinstance(located, list) else []


def in_time_order(profile: MachineProfile, records: list) -> list:
    """The same records, oldest first.

    Machines answer newest-first and the phone stamps an entry when it arrives,
    so appending in the order read would lay yesterday's reading down after
    today's. **All or nothing**: if any record lacks a usable time the set is
    returned exactly as given, because a partial ordering is worse than the
    machine's own.
    """
    if profile.time_path is None:
        return records
    keyed = []
    for index, record in enumerate(records):
        at = instant_at(read_path(record, profile.time_path))
        if at is None:
            return records
        keyed.append((at, index, record))
    keyed.sort(key=lambda item: (item[0], item[1]))
    return [item[2] for item in keyed]


def unseen_records(profile: MachineProfile, records: list, seen_ids: set[str]) -> list:
    """Which records this connector has not already carried across.

    A polling connector re-reads what it has already seen, and a phone that
    accepts the same reading twice has a wrong history, not a duplicated one.
    """
    if profile.id_path is None:
        return records
    out = []
    for record in records:
        identity = read_path(record, profile.id_path)
        if identity is not None and str(identity) not in seen_ids:
            out.append(record)
    return out


class PreparedEntry:
    """One entry ready to add, and the id that stops it being added twice."""

    def __init__(self, identity: str, values: dict, occurred_at: _dt.datetime | None) -> None:
        self.id = identity
        self.values = values
        self.occurred_at = occurred_at


class PreparedRound:
    def __init__(self, entries: list, unreadable: int = 0, still_open: int = 0) -> None:
        self.entries = entries
        self.unreadable = unreadable
        self.still_open = still_open


def stated_time_for(profile: MachineProfile, record: Any, now: _dt.datetime) -> _dt.datetime | None:
    """When to tell the phone this reading was taken, or nothing.

    The reading is worth more than its timestamp: the phone refuses a stated
    time that is in the future or older than it accepts, and that refusal would
    cost the whole record. So a time outside the window is dropped and the entry
    lands stamped on arrival instead of being lost to a quarrel about when it
    happened.
    """
    if profile.time_path is None:
        return None
    at = instant_at(read_path(record, profile.time_path))
    if at is None:
        return None
    if at > now + MAX_FUTURE_SKEW:
        return None
    if now - at > MAX_BACKDATE - _dt.timedelta(hours=1):
        return None
    return at


class _Group:
    """One bucket-and-group, accumulating as records arrive."""

    def __init__(self, bucket_start: _dt.datetime) -> None:
        self.bucket_start = bucket_start
        self.kept: dict[str, Any] = {}
        self.sums: dict[str, float] = {}
        self.counts: dict[str, int] = {}
        self.records = 0

    def add(self, values: dict, rollup: Rollup) -> None:
        self.records += 1
        for key in rollup.group_by:
            if values.get(key) is not None:
                self.kept.setdefault(key, values[key])
        for key, how in rollup.aggregate.items():
            value = values.get(key)
            if value is None:
                continue
            numeric = isinstance(value, (int, float)) and not isinstance(value, bool)
            if how == "first":
                self.kept.setdefault(key, value)
            elif how == "last":
                self.kept[key] = value
            elif how in ("sum", "mean") and numeric:
                self.sums[key] = self.sums.get(key, 0.0) + float(value)
                self.counts[key] = self.counts.get(key, 0) + 1
            elif how == "max" and numeric:
                held = self.kept.get(key)
                if not isinstance(held, (int, float)) or isinstance(held, bool) or value > held:
                    self.kept[key] = value
            elif how == "min" and numeric:
                held = self.kept.get(key)
                if not isinstance(held, (int, float)) or isinstance(held, bool) or value < held:
                    self.kept[key] = value

    def entry(self, identity: str, rollup: Rollup) -> PreparedEntry:
        values = dict(self.kept)
        for key, how in rollup.aggregate.items():
            total, count = self.sums.get(key), self.counts.get(key)
            if total is None or not count:
                continue
            if how in ("sum", "mean"):
                # Rounded to three places: a mean of measured seconds is not
                # more precise than the seconds were, and a full double writes
                # noise.
                values[key] = _rounded(total / count if how == "mean" else total, 3)
        if rollup.count_into:
            values[rollup.count_into] = self.records
        return PreparedEntry(identity, values, self.bucket_start)


def prepare_entries(
    profile: MachineProfile,
    records: list,
    now: _dt.datetime,
    closed_at: _dt.datetime | None = None,
) -> PreparedRound:
    """Turns records into the entries this round should add, oldest first.

    **A bucket is only offered once it has closed.** A group's id names the
    bucket, so offering a half-full one would mean the records that arrive
    afterwards belong to an id already carried, and they would be dropped
    rather than counted.
    """
    rollup = profile.rollup
    if rollup is None:
        unreadable = 0
        entries = []
        for record in in_time_order(profile, records):
            identity = None if profile.id_path is None else read_path(record, profile.id_path)
            if identity is None:
                unreadable += 1
                continue
            entries.append(
                PreparedEntry(
                    str(identity),
                    entry_values(profile, record),
                    stated_time_for(profile, record, now),
                )
            )
        return PreparedRound(entries, unreadable=unreadable)

    width_ms = rollup.every_seconds * 1000
    groups: dict[str, _Group] = {}
    still_open = 0
    # **Ordered before grouping, not merely before sending.** `first` and
    # `last` mean the first and last in TIME; fed the machine's own
    # newest-first order they would quietly mean the opposite.
    for record in in_time_order(profile, records):
        at = stated_time_for(profile, record, now) or now
        millis = int(at.timestamp() * 1000)
        bucket_start = _dt.datetime.fromtimestamp(
            (millis // width_ms) * width_ms / 1000, _dt.timezone.utc
        )
        if not bucket_start + _dt.timedelta(seconds=rollup.every_seconds) < (closed_at or now):
            still_open += 1
            continue
        values = entry_values(profile, record)
        identity = [int(bucket_start.timestamp() * 1000)] + [values.get(k) for k in rollup.group_by]
        digest = hashlib.sha256(compact_json(identity).encode("utf-8")).digest()
        group_id = "rollup-" + b64url(digest).rstrip("=")[:24]
        groups.setdefault(group_id, _Group(bucket_start)).add(values, rollup)
    entries = [group.entry(group_id, rollup) for group_id, group in groups.items()]
    entries.sort(key=lambda entry: entry.occurred_at)
    return PreparedRound(entries, still_open=still_open)


def command_id_for(grant_id: str, record_id: str, sequence: int) -> str:
    """The command id for one record, stable across every attempt at it.

    **Derived, not random.** The phone recognises a command it has already
    carried out by its id; a fresh id for every attempt would append a reading
    twice whenever an acknowledgement was lost. The sequence is part of it
    because the phone compares repeated ids by the command's BYTES.
    """
    digest = hashlib.sha256(compact_json([grant_id, record_id, sequence]).encode("utf-8")).digest()
    return b64url(digest).rstrip("=")[:32]


# --- reading the machine ----------------------------------------------------

MAX_MACHINE_REPLY_BYTES = 16 * 1024 * 1024
REPLY_DEADLINE = 30.0
MIN_INTERVAL_SECONDS = 5
MAX_REMEMBERED_IDS = 1000


def read_credentials(path: str, warn=lambda line: None) -> dict:
    """`key: value` lines from a file only you can read.

    Only the header block before any indented structure: a machine's own
    configuration often follows in the same file and its `key: value` lines
    must never be mistaken for credentials. Nothing read here is ever printed.
    """
    if not os.path.exists(path):
        return {}
    out: dict[str, str] = {}
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle.read().splitlines():
            if line.startswith(" ") or line.startswith("\t"):
                break
            if line.startswith("#"):
                continue
            separator = line.find(":")
            if separator <= 0:
                continue
            key, value = line[:separator].strip(), line[separator + 1 :].strip()
            if not key or not value or " " in key:
                continue
            if key in out:
                if out[key] != value:
                    warn(
                        f'"{key}" is given twice in {path} with two different values; the first '
                        "one is the one being used. If you meant to replace it, change that line "
                        "rather than adding one below it."
                    )
                continue
            out[key] = value
    return out


def without_secrets(url: str) -> str:
    """An address with anything secret in it removed, for printing.

    Some machines are reached at `https://token@host/`. The credentials file is
    never printed, and an address read from it must not become the exception.
    """
    parsed = urllib.parse.urlsplit(url if "//" in url else "//" + url)
    if not parsed.hostname:
        return "(an address that could not be read)"
    scheme = f"{parsed.scheme}://" if parsed.scheme else ""
    port = f":{parsed.port}" if parsed.port else ""
    return f"{scheme}{parsed.hostname}{port}"


def narrowing_advice(profile: MachineProfile) -> str:
    if profile.limit_param is None:
        return (
            "this profile cannot ask this machine for less, because it does not name the "
            'query parameter the machine narrows by — add "limit_param" to its "source"'
        )
    return "ask it a narrower question with --limit"


def memory_overflow_notice(records: int, profile: MachineProfile) -> str | None:
    """Said when one round read more records than this connector can remember
    having carried, which is how the same record gets added for ever."""
    if records < MAX_REMEMBERED_IDS:
        return None
    return (
        f"this round read {records} records, at or past the {MAX_REMEMBERED_IDS} record ids "
        "this connector remembers. The oldest fall out of memory while the machine is still "
        f"offering them, so they would be added again every round: {narrowing_advice(profile)}."
    )


def unusable_window_notice(profile: MachineProfile, limit: Any, since_minutes: Any) -> str | None:
    """The window you asked for that this profile cannot ask the machine for.

    Only what was PASSED is reported: both flags have defaults nobody typed,
    and warning about those would be noise on every single run.
    """
    if profile.source_kind == "mqtt":
        passed = [name for name, value in (("--limit", limit), ("--since-minutes", since_minutes)) if value is not None]
        if not passed:
            return None
        verb = "does" if len(passed) == 1 else "do"
        return (
            f"{' and '.join(passed)} {verb} nothing for {profile.name}: it announces its "
            "records over a broker rather than answering a question, so there is no window "
            "to ask for."
        )
    unusable = []
    if limit is not None and profile.limit_param is None:
        unusable.append('--limit ("limit_param")')
    if since_minutes is not None and profile.since_param is None:
        unusable.append('--since-minutes ("since_param")')
    if not unusable:
        return None
    return (
        f"{' and '.join(unusable)} cannot be asked of {profile.name}: its profile does not "
        "name the query parameter the machine narrows by, so the value is dropped and the "
        "machine answers with whatever it would have answered anyway."
    )


class RecordSource:
    """Where a round's records come from. Two ways of getting them, one shape."""

    def take(self) -> list:
        raise NotImplementedError

    def reconnect(self) -> None:
        raise NotImplementedError

    def close(self) -> None:
        pass


def _credential(profile_key: str, credentials: dict) -> str | None:
    """The environment first, then the file. Never a profile."""
    from_environment = os.environ.get(f"MDS_{profile_key.upper()}")
    if from_environment:
        return from_environment
    value = credentials.get(profile_key)
    return value or None


class HttpMachine(RecordSource):
    """A machine polled over HTTP, which is every profile that is not a broker."""

    def __init__(self, base_url: str, profile: MachineProfile, credentials: dict) -> None:
        self.base_url = base_url
        self.profile = profile
        self.credentials = credentials
        self.window: int | None = None
        self.window_minutes: int | None = None
        self._cookie: str | None = None
        self._authorization: str | None = None
        # A machine on the home network usually carries its own certificate.
        # Accepted for this connector and nothing else: the connection stays on
        # the local network and carries no data outward.
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        self._opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))

    def authenticate(self) -> None:
        profile = self.profile
        kind = profile.auth_kind
        if kind == "none":
            return
        if kind == "bearer":
            token = _credential(profile.token_key, self.credentials)
            if token is None:
                raise Refused(f'no credential named "{profile.token_key}"')
            self._authorization = f"Bearer {token}"
            return
        if kind == "header":
            token = _credential(profile.token_key, self.credentials)
            if token is None or profile.auth_header is None:
                raise Refused("this profile needs a header name and a credential")
            self._authorization = token
            return
        if kind == "basic":
            user = _credential(profile.user_key, self.credentials)
            password = _credential(profile.password_key, self.credentials)
            if user is None or password is None:
                raise Refused("no sign-in credentials")
            encoded = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
            self._authorization = f"Basic {encoded}"
            return
        if kind == "cookie_login":
            user = _credential(profile.user_key, self.credentials)
            password = _credential(profile.password_key, self.credentials)
            if user is None or password is None or profile.login_path is None:
                raise Refused("this profile needs a login path and sign-in credentials")
            body = compact_json(
                {profile.user_field: user, profile.password_field: password}
            ).encode("utf-8")
            request = urllib.request.Request(
                f"{self.base_url}{profile.login_path}", data=body, method="POST"
            )
            # The profile's headers describe the machine, not one request to
            # it: an API that needs `Accept: application/json` to answer needs
            # it to sign in as well.
            for name, value in profile.headers.items():
                request.add_header(name, value)
            request.add_header("Content-Type", "application/json")
            try:
                with self._opener.open(request, timeout=REPLY_DEADLINE) as response:
                    cookies = response.headers.get_all("Set-Cookie") or []
                    response.read(1)
            except urllib.error.HTTPError as error:
                raise Refused(f"the machine refused the sign-in ({error.code})")
            except (urllib.error.URLError, OSError) as error:
                raise Refused(f"the machine could not be reached to sign in: {error}")
            pairs = [cookie.split(";", 1)[0].strip() for cookie in cookies]
            pairs = [pair for pair in pairs if "=" in pair]
            if not pairs:
                raise Refused("the machine returned no session")
            self._cookie = "; ".join(pairs)
            return
        raise Refused(f'this connector does not know the sign-in kind "{kind}"')

    def read(self, limit: int | None = None, since_minutes: int | None = None) -> list:
        profile = self.profile
        query = dict(profile.query)
        if profile.limit_param and limit is not None:
            query[profile.limit_param] = str(limit)
        if profile.since_param and since_minutes is not None:
            since = utc_now() - _dt.timedelta(minutes=since_minutes)
            query[profile.since_param] = str(round(since.timestamp()))
        url = f"{self.base_url}{profile.request_path}"
        if query:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(query)
        request = urllib.request.Request(url)
        for name, value in profile.headers.items():
            request.add_header(name, value)
        if self._cookie:
            request.add_header("Cookie", self._cookie)
        if self._authorization:
            request.add_header(profile.auth_header or "Authorization", self._authorization)
        try:
            with self._opener.open(request, timeout=REPLY_DEADLINE) as response:
                body = self._read_bounded(response)
        except urllib.error.HTTPError as error:
            # The status before the body: a refusal's page is of no interest,
            # and reading it first buffers a log that is thrown away.
            raise Refused(f"the machine refused the read ({error.code})")
        except (urllib.error.URLError, OSError) as error:
            raise Refused(f"the machine could not be read: {error}")
        try:
            decoded = json.loads(body)
        except ValueError:
            raise Refused("the machine did not answer with JSON")
        return select_records(profile, decoded)

    def _read_bounded(self, response) -> str:
        """A deadline bounds waiting, not allocating.

        A recorder wedged into a loop, or a hub that answers a poll with its
        whole history, can stream faster than any timeout will fit — and this
        connector is a long-running process by design, so what that produces is
        not a failed round but an out-of-memory kill of the thing whose job is
        to keep carrying.
        """
        cap = MAX_MACHINE_REPLY_BYTES
        readable = f"{cap // (1024 * 1024)} MB" if cap >= 1024 * 1024 else f"{cap} bytes"
        declared = response.headers.get("Content-Length")
        if declared is not None and declared.isdigit() and int(declared) > cap:
            raise Refused(
                f"the machine answered with more than {readable} (it declared {declared} "
                f"bytes); {narrowing_advice(self.profile)}"
            )
        chunks = []
        total = 0
        while True:
            chunk = response.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > cap:
                raise Refused(
                    f"the machine answered with more than {readable} (it was still sending "
                    f"at {total} bytes); {narrowing_advice(self.profile)}"
                )
            chunks.append(chunk)
        return b"".join(chunks).decode("utf-8", errors="replace")

    def take(self) -> list:
        return self.read(limit=self.window, since_minutes=self.window_minutes)

    def reconnect(self) -> None:
        self.authenticate()


# --- machines that announce, rather than wait to be asked --------------------
#
# A minimal MQTT 3.1.1 subscriber. **Subscribe only**, and there will be no
# publish here: this connector reads a machine and writes to a phone, and a
# client that could publish would be a way to make somebody's camera system do
# things. Written out rather than pulled in as a dependency because what is
# needed is four packet types and a keepalive.


class MqttRefused(Refused):
    pass


def _mqtt_string(value: str) -> bytes:
    raw = value.encode("utf-8")
    return bytes([len(raw) >> 8, len(raw) & 0xFF]) + raw


def _mqtt_remaining_length(length: int) -> bytes:
    """MQTT's variable-length integer: seven bits at a time, top bit as 'more'."""
    out = bytearray()
    remaining = length
    while True:
        byte = remaining % 128
        remaining //= 128
        if remaining > 0:
            byte |= 0x80
        out.append(byte)
        if remaining == 0:
            return bytes(out)


_CONNACK_REASONS = {
    1: "the broker does not speak MQTT 3.1.1",
    2: "the broker rejected this client id",
    3: "the broker is not available",
    4: "the broker rejected the user name or password",
    5: "the broker did not authorise this client",
}


class BrokerMachine(RecordSource):
    """Messages accumulate as they arrive and are handed over whole at each round.

    The round machinery is untouched: the same ids, ordering, rollup, rate and
    state apply, so subscribing changes when records appear and nothing about
    what happens to them.
    """

    MAX_WAITING = 5000

    def __init__(self, profile: MachineProfile, credentials: dict, warn=lambda line: None) -> None:
        self.profile = profile
        self.credentials = credentials
        self.warn = warn
        self._socket: socket.socket | None = None
        self._buffer = bytearray()
        self._waiting: list = []
        self.dropped = 0

    def open(self, host: str) -> None:
        profile = self.profile
        user = _credential(profile.user_key, self.credentials)
        password = _credential(profile.password_key, self.credentials)
        # 3.1.2.9: a password may not be sent without a user name. Leaving both
        # out would sign this connector in as nobody while the owner reads a
        # password in their file and believes otherwise.
        if password is not None and user is None:
            raise MqttRefused(
                "this profile has a broker password but no user name, and MQTT 3.1.1 cannot "
                "send one without the other — add the user credential, or remove the password"
            )
        address, _, port_text = host.partition(":")
        port = int(port_text) if port_text.isdigit() else profile.broker_port
        try:
            sock = socket.create_connection((address, port), timeout=20.0)
        except OSError as error:
            raise MqttRefused(f"could not reach the broker at {address}:{port} ({error})")
        sock.settimeout(20.0)
        self._socket = sock
        client_id = "mds-connector-" + "".join(random.choice("0123456789abcdef") for _ in range(12))
        flags = 0x02 | (0x80 if user else 0) | (0x40 if user and password else 0)
        body = (
            _mqtt_string("MQTT")
            + bytes([4, flags, 0, 30])
            + _mqtt_string(client_id)
            + (_mqtt_string(user) if user else b"")
            + (_mqtt_string(password) if user and password else b"")
        )
        sock.sendall(bytes([0x10]) + _mqtt_remaining_length(len(body)) + body)
        connack = self._await_packet(2)
        if len(connack[2]) < 2 or connack[2][1] != 0:
            code = 255 if len(connack[2]) < 2 else connack[2][1]
            raise MqttRefused(
                _CONNACK_REASONS.get(code, f"the broker refused the connection (code {code})")
            )
        subscribe = bytes([0, 1]) + _mqtt_string(profile.broker_topic) + bytes([1])
        sock.sendall(bytes([0x82]) + _mqtt_remaining_length(len(subscribe)) + subscribe)
        suback = self._await_packet(9)
        # 0x80 is the broker saying "not that topic". A subscriber that carried
        # on would sit silent for ever looking exactly like a quiet machine.
        if len(suback[2]) < 3 or suback[2][-1] >= 0x80:
            raise MqttRefused(f'the broker refused the subscription to "{profile.broker_topic}"')
        sock.settimeout(0.2)

    def _packets(self, chunk: bytes) -> Iterable[tuple[int, int, bytes]]:
        self._buffer += chunk
        while True:
            if len(self._buffer) < 2:
                return
            multiplier, length, index = 1, 0, 1
            while True:
                if index >= len(self._buffer):
                    return
                byte = self._buffer[index]
                length += (byte & 0x7F) * multiplier
                index += 1
                if not byte & 0x80:
                    break
                multiplier *= 128
                if multiplier > 128 ** 3:
                    raise MqttRefused("the broker sent an unreadable packet length")
            if length > 1 << 20:
                raise MqttRefused("the broker sent a packet larger than this connector accepts")
            if len(self._buffer) < index + length:
                return
            header = self._buffer[0]
            payload = bytes(self._buffer[index : index + length])
            del self._buffer[: index + length]
            yield header >> 4, header & 0x0F, payload

    def _await_packet(self, kind: int) -> tuple[int, int, bytes]:
        assert self._socket is not None
        deadline = time.monotonic() + 20.0
        while time.monotonic() < deadline:
            chunk = self._socket.recv(65536)
            if not chunk:
                raise MqttRefused("the broker closed before it answered")
            for packet in self._packets(chunk):
                if packet[0] == kind:
                    return packet
        raise MqttRefused("the broker did not answer in time")

    def _drain(self) -> None:
        assert self._socket is not None
        while True:
            try:
                chunk = self._socket.recv(65536)
            except socket.timeout:
                return
            except OSError as error:
                raise MqttRefused(f"the broker connection failed: {error}")
            if not chunk:
                raise MqttRefused("the broker closed the connection")
            for kind, flags, payload in self._packets(chunk):
                if kind != 3:
                    continue
                decoded = self._decode_publish(flags, payload)
                if decoded is None:
                    continue
                message, packet_id = decoded
                if packet_id is not None:
                    # QoS 1 is acknowledged, so the broker stops redelivering.
                    # This connector's own record ids make a redelivery
                    # harmless either way.
                    self._socket.sendall(
                        bytes([0x40, 0x02, packet_id >> 8, packet_id & 0xFF])
                    )
                try:
                    document = json.loads(message.decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    continue
                for record in select_records(self.profile, document):
                    if len(self._waiting) >= self.MAX_WAITING:
                        self._waiting.pop(0)
                        self.dropped += 1
                    self._waiting.append(record)

    @staticmethod
    def _decode_publish(flags: int, payload: bytes) -> tuple[bytes, int | None] | None:
        qos = (flags >> 1) & 0x03
        if len(payload) < 2:
            return None
        topic_length = (payload[0] << 8) | payload[1]
        if len(payload) < 2 + topic_length:
            return None
        offset = 2 + topic_length
        packet_id = None
        if qos > 0:
            if len(payload) < offset + 2:
                return None
            packet_id = (payload[offset] << 8) | payload[offset + 1]
            offset += 2
        return payload[offset:], packet_id

    def listen(self, seconds: float) -> None:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            self._drain()

    def take(self) -> list:
        self._drain()
        if self.dropped:
            # Said out loud. Silently discarding what a machine announced is
            # the one outcome this connector is built to avoid.
            self.warn(
                f"{self.dropped} announcement(s) were dropped: more than {self.MAX_WAITING} "
                "piled up while the phone was unreachable"
            )
            self.dropped = 0
        taken, self._waiting = self._waiting, []
        return taken

    def reconnect(self) -> None:
        host = _credential(self.profile.url_key, self.credentials)
        self.close()
        if host:
            self.open(re.sub(r"^[a-z]+://", "", host))

    def close(self) -> None:
        if self._socket is None:
            return
        try:
            self._socket.sendall(bytes([0xE0, 0x00]))
        except OSError:
            pass  # Saying goodbye is a courtesy, not a requirement.
        try:
            self._socket.close()
        except OSError:
            pass
        self._socket = None


# --- what this connector remembers between runs ------------------------------


class State:
    """**Its own key lives here, so this file is a secret.**

    A tool that generated a fresh key every run would have to be approved again
    every run, which is not a connected tool but a stranger knocking
    repeatedly. It is written with owner-only permissions and never printed.

    The sequence is here for the same reason: a command's sequence must
    increase per permission, and the phone remembers the watermark, so a
    counter kept only in memory would restart at 1 after a reboot and have
    every command refused as a replay.
    """

    def __init__(self, raw: dict) -> None:
        self.raw = raw

    @staticmethod
    def fresh() -> "State":
        keys = PodKeys.generate()
        return State(
            {
                "signing_seed": b64url(keys.signing_seed),
                "exchange_seed": b64url(keys.exchange_seed),
                "tool_did": keys.did,
                "sequence": 0,
                "carried_ids": [],
                "commands_in_window": 0,
            }
        )

    @staticmethod
    def read(path: str) -> "State | None":
        """The state in [path], or nothing.

        Raises if the file is there and cannot be read. **A file that exists
        but is unreadable must never be answered with "no state"**: the caller
        would mint a fresh key, and the connection the owner approved — which
        lives only here — would be gone, silently, with the permission left on
        their phone pointing at a tool that no longer holds the key.
        """
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as handle:
                decoded = json.load(handle)
        except Exception as error:
            raise Refused(f"{path} is not readable as this connector's state: {error}")
        if not isinstance(decoded, dict):
            raise Refused(f"{path} does not hold this connector's key")
        for key in ("signing_seed", "exchange_seed", "tool_did"):
            if not isinstance(decoded.get(key), str):
                raise Refused(f"{path} does not hold this connector's key")
        return State(decoded)

    def write(self, path: str) -> None:
        """Written to a temporary file and renamed over the target, so a crash
        mid-write leaves either the old state or the new one and never a
        truncated file."""
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)
        temporary = path + ".new"
        # Restricted BEFORE the key goes in. Writing first and narrowing after
        # leaves a window, and on a shared machine that window is the whole of
        # what somebody needs.
        handle = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(handle, compact_json(self.raw).encode("utf-8"))
        finally:
            os.close(handle)
        os.chmod(temporary, stat.S_IRUSR | stat.S_IWUSR)
        os.replace(temporary, path)

    # -- the pieces the round reads and writes --
    @property
    def keys(self) -> PodKeys:
        return PodKeys(unb64url(self.raw["signing_seed"]), unb64url(self.raw["exchange_seed"]))

    @property
    def is_connected(self) -> bool:
        return bool(self.raw.get("pod_did")) and bool(self.raw.get("grant_id"))

    @property
    def grant_id(self) -> str:
        return self.raw["grant_id"]

    @property
    def pod_did(self) -> str:
        return self.raw["pod_did"]

    @property
    def sequence(self) -> int:
        return int(self.raw.get("sequence", 0))

    @property
    def carried_ids(self) -> list:
        return list(self.raw.get("carried_ids", []))

    @property
    def in_flight(self) -> dict | None:
        held = self.raw.get("in_flight")
        return held if isinstance(held, dict) else None

    def budget_at(self, now: _dt.datetime) -> tuple[int, _dt.datetime] | None:
        """How many more commands this connector may send before the window
        rolls over, and when it does.

        Counted from the first command of the window rather than a wall-clock
        boundary, which is conservative: it can only ever wait longer than the
        phone would.
        """
        maximum = self.raw.get("quota_max_commands")
        seconds = self.raw.get("quota_window_seconds")
        if not isinstance(maximum, int) or not isinstance(seconds, int) or seconds <= 0:
            return None
        started = parse_wire_time(self.raw.get("window_started_at"))
        if started is None or not started + _dt.timedelta(seconds=seconds) > now:
            return maximum, now + _dt.timedelta(seconds=seconds)
        return maximum - int(self.raw.get("commands_in_window", 0)), started + _dt.timedelta(seconds=seconds)

    def spend(self, now: _dt.datetime) -> None:
        seconds = self.raw.get("quota_window_seconds")
        if not isinstance(seconds, int):
            return
        started = parse_wire_time(self.raw.get("window_started_at"))
        rolled = started is None or not started + _dt.timedelta(seconds=seconds) > now
        self.raw["window_started_at"] = wire_time(now if rolled else started)
        self.raw["commands_in_window"] = 1 if rolled else int(self.raw.get("commands_in_window", 0)) + 1

    def carried(self, identity: str, sequence: int) -> None:
        """Remembered, oldest forgotten past the bound, and nothing left in
        flight — a record that is settled is no longer waiting on an answer."""
        kept = [seen for seen in self.carried_ids if seen != identity] + [identity]
        self.raw["sequence"] = sequence
        self.raw["carried_ids"] = kept[-MAX_REMEMBERED_IDS:]
        self.raw.pop("in_flight", None)


def replayable_at(in_flight: dict, now: _dt.datetime) -> bool:
    """Whether an identical replay can still be accepted.

    The phone refuses a command whose issue time is further back than it
    accepts, so past that point the exact bytes are worthless and only a fresh
    command can carry the record.
    """
    issued = parse_wire_time(in_flight.get("issued_at"))
    if issued is None:
        return False
    return now - issued < MAX_COMMAND_AGE - _dt.timedelta(seconds=30)


# How one round ended.
FINISHED, STOPPED, WAIT, ENDED = "finished", "stopped", "wait", "ended"


class RoundResult:
    def __init__(self, outcome: str, refusal: str | None = None) -> None:
        self.outcome = outcome
        self.refusal = refusal


def carry_round(
    profile: MachineProfile,
    records: list,
    state: State,
    state_path: str,
    host: str,
    port: int,
    space_id: str,
    say=print,
    warn=lambda line: None,
) -> RoundResult:
    """One pass: carry across every reading the phone has not already been given.

    State is written after EVERY accepted entry, not once at the end. A
    connector that saved on the way out would, after a crash, re-add everything
    it had already carried — and a phone holding one reading twice has a wrong
    history, not a duplicated one.
    """
    now = utc_now()
    prepared = prepare_entries(profile, records, now=now)

    if prepared.unreadable:
        say(
            f'{prepared.unreadable} record(s) have no "{profile.id_path}" and cannot be told '
            "apart from a re-read, so they were not carried"
        )

    seen = set(state.carried_ids)
    fresh = [entry for entry in prepared.entries if entry.id not in seen]
    pending = [entry for entry in fresh if entry.values]

    # A decision, not a skip: these have nothing this profile maps, and
    # remembering them is what stops them being reconsidered on every round.
    for entry in fresh:
        if not entry.values:
            state.carried(entry.id, state.sequence)
            state.write(state_path)

    replay = state.in_flight
    if not pending and replay is None:
        still = f" ({prepared.still_open} still inside an open bucket)" if prepared.still_open else ""
        say(f"nothing new{still}")
        return RoundResult(FINISHED)

    keys = state.keys
    carried = 0
    already_there = 0
    refusal: str | None = None

    with PodLink.connect_to(host, port, state.pod_did, keys) as link:

        def offer(identity: str, values: dict, occurred_at: _dt.datetime | None) -> str:
            nonlocal carried, already_there, refusal
            for _ in range(3):
                # **Stop before the phone has to refuse.** Spending the window
                # down to its limit means the last readings of every window
                # come back refused rather than chosen between, and those
                # refusals are what the owner reads in the tool's history.
                budget = state.budget_at(utc_now())
                if budget is not None and budget[0] <= 0:
                    say(
                        "the rate you allowed for this window is used up — it starts again at "
                        + wire_time(budget[1])
                    )
                    # Cleared: this round stopped on OUR count, and the last
                    # thing the phone said was that an entry succeeded.
                    refusal = None
                    return WAIT
                held = state.in_flight
                replaying = (
                    held is not None
                    and held.get("record_id") == identity
                    and held.get("space_id") == space_id
                    and replayable_at(held, utc_now())
                )
                if replaying:
                    sequence = int(held["sequence"])
                    command_id = held["command_id"]
                    issued_at = parse_wire_time(held["issued_at"])
                    sent_values = held["values"]
                    sent_occurred = parse_wire_time(held.get("occurred_at"))
                else:
                    sequence = state.sequence + 1
                    command_id = command_id_for(state.grant_id, identity, sequence)
                    issued_at = utc_now()
                    sent_values = values
                    sent_occurred = occurred_at

                # **Recorded before it is sent.** If the answer never arrives,
                # this is the only evidence that the phone may already hold
                # this reading. The spend is counted here too: a command whose
                # answer is lost still used the rate you allowed.
                state.raw["in_flight"] = {
                    "command_id": command_id,
                    "record_id": identity,
                    "space_id": space_id,
                    "sequence": sequence,
                    "issued_at": wire_time(issued_at),
                    "values": sent_values,
                    "occurred_at": wire_time(sent_occurred) if sent_occurred else None,
                }
                state.spend(utc_now())
                state.write(state_path)

                command = ToolCommand(
                    command_id, state.grant_id, sequence, issued_at, space_id, sent_values, sent_occurred
                ).sign(keys)
                ack = send_append(link, keys, command)
                refusal = ack.outcome
                disposition = disposition_for(ack.outcome)
                if disposition in (CARRIED, ALREADY_THERE):
                    state.carried(identity, sequence)
                    state.write(state_path)
                    if disposition == CARRIED:
                        carried += 1
                    else:
                        already_there += 1
                    return FINISHED
                if disposition == RETRY:
                    # These exact bytes cannot land: move the sequence on, drop
                    # what was in flight and build a fresh command.
                    state.raw["sequence"] = sequence
                    state.raw.pop("in_flight", None)
                    state.write(state_path)
                    continue
                state.raw.pop("in_flight", None)
                state.write(state_path)
                return {WAIT_LONGER: WAIT, STOP: ENDED}.get(disposition, STOPPED)
            say(f"the phone refused record {identity} as a replay three times, so it is left "
                "for the next round")
            return STOPPED

        outcome = FINISHED
        # Anything left in flight is settled FIRST, always. **Only one command
        # can be in flight at a time**: offering any other record first
        # overwrites the exact bytes that are the only evidence the phone may
        # already hold this reading.
        if replay is not None:
            outcome = offer(replay["record_id"], replay["values"], parse_wire_time(replay.get("occurred_at")))

        if outcome == FINISHED:
            for entry in pending:
                if replay is not None and entry.id == replay.get("record_id"):
                    continue
                outcome = offer(entry.id, entry.values, entry.occurred_at)
                if outcome != FINISHED:
                    break

    settled = ", ".join(
        part
        for part in (
            f"added {carried}" if carried else "",
            # Counted apart from what this round added: a reading the phone
            # already had is not work this connector did.
            f"already there {already_there}" if already_there else "",
        )
        if part
    )
    tail = "" if outcome == FINISHED else f" ({plainly(refusal)})"
    say((settled or "carried nothing") + tail)
    return RoundResult(outcome, None if outcome == FINISHED else refusal)


def read_once_more(source: RecordSource, warn=lambda line: None) -> list:
    """Everything the source has, with exactly one fresh connection if the
    first attempt fails.

    Sessions expire and brokers drop: a cookie that was good an hour ago is not
    evidence it is good now. One retry rather than a loop — if a fresh
    connection cannot read either, the machine is away and the round is what
    should be lost, not the connector.
    """
    try:
        return source.take()
    except Refused as error:
        source.reconnect()
        warn(f"connected again after: {error}")
        return source.take()


def carry_continuously(
    profile: MachineProfile,
    source: RecordSource,
    first: list,
    state: State,
    state_path: str,
    host: str,
    port: int,
    space_id: str,
    interval: int | None,
    say=print,
    warn=lambda line: None,
    sleep=time.sleep,
    rounds: int | None = None,
) -> int:
    """Rounds, one after another, for as long as this connector should keep going."""
    pending = first
    wait_multiplier = 1
    completed = 0
    code = 0

    while rounds is None or completed < rounds:
        completed += 1
        notice = memory_overflow_notice(len(pending), profile)
        if notice:
            warn(notice)
        try:
            result = carry_round(
                profile, pending, state, state_path, host, port, space_id, say=say, warn=warn
            )
            if result.outcome == FINISHED:
                wait_multiplier = 1
            elif result.outcome in (STOPPED, WAIT):
                # **Both back off, and for the same reason.** A stopped round
                # usually stops again, and a command is counted against your
                # rate when it is sent rather than when it succeeds — so
                # retrying at the full interval hammers the phone AND drains
                # the allowance.
                wait_multiplier = min(wait_multiplier * 2, 20)
                held = f"{interval * wait_multiplier}s " if interval else ""
                say(f"holding off {held}({plainly(result.refusal)})")
                if interval is None:
                    code = 70 if result.outcome == STOPPED else 75
            else:
                warn(
                    f"This connector is finished: {plainly(result.refusal)}.\n"
                    "Nothing it does from here can change that. Connect it again in\n"
                    "My data → Connected tools if that was not intended."
                )
                return 69
        except Refused as error:
            warn(f"round failed: {error}")
            # **The file is authoritative after a failure.** The round writes
            # after every accepted entry, so carrying on from an in-memory copy
            # taken before it would re-add everything it had already delivered.
            try:
                reread = State.read(state_path)
                if reread is not None:
                    state = reread
            except Refused as unreadable:
                warn(f"the state file could not be re-read: {unreadable}")
                return 70
            if interval is None:
                return 70
        if interval is None:
            break
        sleep(interval * wait_multiplier)
        try:
            pending = read_once_more(source, warn=warn)
        except Refused as error:
            # A machine that will not answer costs this round, not the connector.
            warn(f"could not read the machine: {error}")
            pending = []
    return code


# --- finding a profile ------------------------------------------------------

HERE = os.path.dirname(os.path.abspath(__file__))
PROFILE_DIRECTORY = os.path.join(HERE, "profiles")


def shipped_profiles() -> list[str]:
    if not os.path.isdir(PROFILE_DIRECTORY):
        return []
    return sorted(
        name[:-5] for name in os.listdir(PROFILE_DIRECTORY) if name.endswith(".json")
    )


def resolve_profile(named: str) -> MachineProfile:
    """A name from the shipped set, or a path to one you wrote yourself."""
    candidates = [
        os.path.join(PROFILE_DIRECTORY, f"{named}.json"),
        named,
        f"{named}.json",
    ]
    for path in candidates:
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    raw = json.load(handle)
            except Exception as error:
                raise Refused(f"{path} is not readable as a profile: {error}")
            profile, refusal = MachineProfile.parse(raw)
            if profile is None:
                raise Refused(f"{path} cannot be carried out: {refusal}")
            return profile
    known = ", ".join(shipped_profiles()) or "(none found)"
    raise Refused(
        f'no profile called "{named}".\n'
        f"This connector ships with: {known}\n"
        "Or pass the path to a profile file you wrote yourself."
    )


# --- the commands a person types --------------------------------------------

DEFAULT_HOME = os.path.join(os.path.expanduser("~"), ".mds-connector")


def _stamped(line: str) -> None:
    print(f"{utc_now().strftime('%H:%M:%S')}  {line}", flush=True)


def _warn(line: str) -> None:
    sys.stderr.write(line.rstrip("\n") + "\n")
    sys.stderr.flush()


def _state_path(options, profile: MachineProfile) -> str:
    return options.state or os.path.join(DEFAULT_HOME, f"{profile.topic_slug}.json")


def _credentials_for(options, warn=_warn) -> tuple[dict, str]:
    path = (
        options.credentials
        or os.environ.get("MDS_CONNECTOR_CREDENTIALS")
        or os.path.join(DEFAULT_HOME, "credentials")
    )
    return read_credentials(path, warn=warn), path


def _base_url(profile: MachineProfile, credentials: dict, path: str) -> str:
    raw = (_credential(profile.url_key, credentials) or "").strip()
    if not raw:
        raise Refused(
            f"No address for {profile.name}.\n"
            f'This profile reads it from the credential named "{profile.url_key}" in {path},\n'
            f"or from MDS_{profile.url_key.upper()} in the environment."
        )
    return re.sub(r"/+$", "", raw)


def _source_for(profile: MachineProfile, credentials: dict, base_url: str) -> RecordSource:
    if profile.source_kind == "mqtt":
        broker = BrokerMachine(profile, credentials, warn=_warn)
        broker.open(re.sub(r"^[a-z]+://", "", base_url))
        return broker
    machine = HttpMachine(base_url, profile, credentials)
    machine.authenticate()
    return machine


def command_profiles(_options) -> int:
    names = shipped_profiles()
    if not names:
        print("No profiles are installed beside this connector.")
        return 0
    print("Machines this connector already knows how to read:\n")
    for name in names:
        try:
            profile = resolve_profile(name)
        except Refused as error:
            print(f"  {name:<22} (unusable: {error})")
            continue
        print(f"  {name:<22} {profile.name}")
    print(
        "\nUse one with:  --profile <name>\n"
        "Reading a machine that is not listed means writing a profile for it, not "
        "writing a program."
    )
    return 0


def command_fields(options) -> int:
    profile = resolve_profile(options.profile)
    print(f"Make this topic in the app for {profile.name}:\n")
    print(json.dumps(profile.topic_template, indent=2))
    print(
        "\nIn the app: My data → Topics → New topic, with these fields.\n"
        "Nothing was read from the machine and nothing was written."
    )
    return 0


def command_preview(options) -> int:
    """Signs in, reads recent records, and prints exactly what it would add.

    Needs no phone and no permission. This is the one question a preview
    exists to answer: is the mapping right?
    """
    profile = resolve_profile(options.profile)
    credentials, credentials_path = _credentials_for(options)
    base_url = _base_url(profile, credentials, credentials_path)
    notice = unusable_window_notice(profile, options.limit, options.since_minutes)
    if notice:
        _warn(notice)
    source = _source_for(profile, credentials, base_url)
    try:
        if isinstance(source, BrokerMachine):
            print(
                f"listening to {profile.broker_topic} for {options.listen_seconds}s — the "
                "machine has to announce something for this to show anything"
            )
            source.listen(options.listen_seconds)
            records = source.take()
        else:
            source.window = options.limit if options.limit is not None else 20
            source.window_minutes = options.since_minutes
            records = source.take()
    finally:
        source.close()

    print(f"machine: {profile.name} at {without_secrets(base_url)}")
    print(f"records read: {len(records)}")
    overflow = memory_overflow_notice(len(records), profile)
    if overflow:
        _warn(overflow)
    print("\nentries this connector would add:")
    now = utc_now()
    prepared = prepare_entries(profile, records, now=now)
    for entry in prepared.entries:
        if not entry.values:
            print("  (a record with nothing this profile maps — skipped)")
            continue
        print("  " + compact_json(entry.values))
    if prepared.still_open:
        print(
            f"  ({prepared.still_open} record(s) are inside a bucket that has not closed yet, "
            "and would be carried by a later round)"
        )
        # **Shown anyway, marked as what it is.** For a profile that samples a
        # gauge the current bucket is ALWAYS open, so a preview that stopped
        # here could never show anybody whether their mapping was right.
        ahead = prepare_entries(
            profile,
            records,
            now=now,
            closed_at=now + _dt.timedelta(seconds=profile.rollup.every_seconds + 1),
        )
        print("  once that bucket closes it becomes:")
        for entry in ahead.entries:
            print("    " + compact_json(entry.values))
    if prepared.unreadable:
        print(
            f'  ({prepared.unreadable} record(s) have no "{profile.id_path}" and could not be '
            "told apart from a re-read)"
        )
    print(
        "\nNothing was written. Make the topic ('fields' prints it), then connect this tool\n"
        "with an invite from My data → Connected tools."
    )
    return 0


def _carry(options, profile: MachineProfile, state: State, state_path: str, host: str, port: int) -> int:
    credentials, credentials_path = _credentials_for(options)
    base_url = _base_url(profile, credentials, credentials_path)
    notice = unusable_window_notice(profile, options.limit, options.since_minutes)
    if notice:
        _warn(notice)
    interval = options.every
    # **The window has to cover the gap between reads.** A busy machine can
    # push more than `limit` records past the top between two polls, and
    # anything that falls off is never seen again — silent loss, which is worse
    # than a duplicate.
    limit = options.limit if options.limit is not None else (20 if interval is None else 200)
    if limit >= MAX_REMEMBERED_IDS:
        raise Refused(
            f"--limit {limit} is at or past the {MAX_REMEMBERED_IDS} record ids this connector "
            "remembers,\nso records would fall out of memory while still being read and be "
            "added twice. Use a smaller window."
        )
    since_minutes = options.since_minutes
    if since_minutes is None and interval is not None:
        since_minutes = max(2, -(-interval * 3 // 60))

    source = _source_for(profile, credentials, base_url)
    try:
        if isinstance(source, HttpMachine):
            source.window = limit
            source.window_minutes = since_minutes
        pending = read_once_more(source, warn=_warn)
        return carry_continuously(
            profile,
            source,
            pending,
            state,
            state_path,
            host,
            port,
            options.topic,
            interval,
            say=_stamped,
            warn=_warn,
        )
    finally:
        source.close()


def command_connect(options) -> int:
    """Answers an invite, then keeps carrying."""
    profile = resolve_profile(options.profile)
    invite = Invite.decode(options.invite)
    if invite is None:
        raise Refused(
            "That is not a usable invite.\n"
            "In the app: My data → Connected tools → Create private invite, then copy the\n"
            "whole thing including its 'mds-tool-invite.v1.' beginning."
        )
    if profile.id_path is None:
        # Without an id there is no way to tell a re-read from a new reading.
        raise Refused(
            'This profile has no "id_path", so this connector cannot tell a record it has '
            "already carried from a new one. Add one before letting it write."
        )
    if options.every is not None and options.every < MIN_INTERVAL_SECONDS:
        raise Refused(
            f"--every takes a whole number of seconds, at least {MIN_INTERVAL_SECONDS}. "
            "Anything less polls the machine and the phone hard enough to be the problem."
        )
    state_path = _state_path(options, profile)
    state = State.read(state_path) or State.fresh()
    if state.is_connected and not options.again:
        print(
            f"This connector is already connected (its state is in {state_path}).\n"
            "Use 'run' to keep carrying, or pass --again to connect afresh."
        )
        return 64
    grant, pod_did, _ = connect_tool(
        state.keys, invite, options.name or profile.name, options.topic, say=print
    )
    # A new permission starts its own watermark at zero, and its own budget.
    state.raw.update(
        {
            "pod_did": pod_did,
            "pod_host": invite.host,
            "pod_port": invite.port,
            "grant_id": grant.grant_id,
            "sequence": 0,
            "quota_max_commands": grant.quota["max_commands"],
            "quota_window_seconds": grant.quota["window_seconds"],
            "window_started_at": wire_time(utc_now()),
            "commands_in_window": 0,
        }
    )
    state.raw.pop("in_flight", None)
    state.write(state_path)
    print(f"Connected. Kept in {state_path} — that file holds this tool's key.")
    if options.every is None:
        print("Add --every 30 to keep carrying readings.")
        return 0
    return _carry(options, profile, state, state_path, invite.host, invite.port)


def command_run(options) -> int:
    """Keeps carrying, using the address remembered when it was connected."""
    profile = resolve_profile(options.profile)
    state_path = _state_path(options, profile)
    state = State.read(state_path)
    if state is None or not state.is_connected:
        raise Refused(
            "This connector is not connected to a phone yet.\n"
            "In the app: My data → Connected tools → Create private invite, then run:\n"
            f"  python3 {os.path.basename(__file__)} connect --profile {options.profile} "
            "--topic <topic id> --invite '<paste it here>'"
        )
    host = options.host or state.raw.get("pod_host")
    port = options.port or state.raw.get("pod_port")
    if not host or not port:
        raise Refused(
            "This connector does not know where that phone is any more.\n"
            "Pass --host and --port, or connect again with a fresh invite."
        )
    if options.every is not None and options.every < MIN_INTERVAL_SECONDS:
        raise Refused(
            f"--every takes a whole number of seconds, at least {MIN_INTERVAL_SECONDS}."
        )
    # A phone's address on a home network can change. Remember wherever it
    # actually answered, so the next run needs nothing typed.
    if options.host or options.port:
        state.raw["pod_host"], state.raw["pod_port"] = host, int(port)
        state.write(state_path)
    return _carry(options, profile, state, state_path, host, int(port))


def command_check(_options) -> int:
    """Proves the ciphers against their published test vectors.

    Worth its own command because the one piece written out longhand here —
    HChaCha20 — is a step `cryptography` does not ship, and a key-derivation
    step that is subtly wrong produces bytes that look exactly like working
    encryption right up until nothing can read them.
    """
    subkey = hchacha20(
        bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
        bytes.fromhex("000000090000004a0000000031415927"),
    )
    expected = "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"
    if subkey.hex() != expected:
        _warn("the extended-nonce key derivation does not match its published test vector")
        return 70
    key, nonce = bytes(range(32)), bytes(range(24))
    if xchacha20poly1305_decrypt(key, nonce, xchacha20poly1305_encrypt(key, nonce, b"round trip")) != b"round trip":
        _warn("the payload cipher does not round-trip")
        return 70
    alice, bob = PodKeys.generate(), PodKeys.generate()
    if not verify_signature(b"proof", alice.sign(b"proof"), alice.did):
        _warn("signatures do not verify against the identity that made them")
        return 70
    envelope = seal_envelope({"hello": "there"}, alice, bob.did, bob.exchange_public_key)
    if open_envelope(envelope, bob) != {"hello": "there"}:
        _warn("a sealed envelope does not open for its recipient")
        return 70
    first = PeerSession.derive(alice, bob.encoded_exchange_key, "shared-nonce")
    second = PeerSession.derive(bob, alice.encoded_exchange_key, "shared-nonce")
    if second.open(first.seal(b"frame")) != b"frame":
        _warn("two ends of a connection do not agree on a session key")
        return 70
    if not _refusals_hold():
        return 70
    print("Ciphers, identities, sealed payloads and session keys all check out.")
    print("Tampered permissions, forged senders and mismatched answers are all refused.")
    profiles = shipped_profiles()
    for name in profiles:
        resolve_profile(name)
    print(f"{len(profiles)} shipped profile(s) parse.")
    return 0



def _refusals_hold() -> bool:
    """The doors that matter, each proved by something that must NOT get through.

    Every one of these is a way a carrier on the network could hand this
    connector something that looks right. A door nothing ever pushes on is a
    door nobody knows is shut.
    """
    phone, tool, stranger = PodKeys.generate(), PodKeys.generate(), PodKeys.generate()
    session_id, challenge = "session-1", "challenge-1"

    def grant_for(owner: PodKeys, claim_overrides: dict | None = None) -> ToolGrant:
        claim = {
            "grant_id": "grant-1",
            "tool_did": tool.did,
            "owner_did": owner.did,
            "actions": ["appendEntry"],
            "scope": {"topics": [{"space_id": "space-1"}]},
            "quota": {"max_commands": 10, "window_seconds": 3600},
            "issued_at": wire_time(utc_now()),
        }
        protected = canonical_bytes(claim)
        return ToolGrant({**claim, **(claim_overrides or {}),
                          "protected": b64url(protected),
                          "signature": owner.sign(protected)})

    def sealed(grant: ToolGrant, sender: PodKeys = phone, transcript: str | None = None) -> dict:
        return seal_envelope(
            {
                "grant": grant.raw,
                "transcript": transcript
                if transcript is not None
                else grant_transcript(session_id, challenge, grant),
            },
            sender,
            tool.did,
            tool.exchange_public_key,
        )

    def refused(what: str, action) -> bool:
        try:
            action()
        except (Refused, DecryptionFailed):
            return True
        _warn(f"a {what} was NOT refused")
        return False

    honest = grant_for(phone)
    if open_sealed_grant(sealed(honest, phone), session_id, challenge, phone.did, tool).grant_id != "grant-1":
        _warn("an honest permission did not open")
        return False

    checks = [
        # The readable claim rewritten while the signed bytes stay valid: the
        # actions a reader acts on would not be the actions that were signed.
        ("widened permission", lambda: open_sealed_grant(
            sealed(grant_for(phone, {"actions": ["appendEntry", "readEntries"]})),
            session_id, challenge, phone.did, tool)),
        # Correctly sealed, by the wrong party. This tool's address is public,
        # so anybody can produce a perfectly valid envelope for it.
        ("permission from a stranger", lambda: open_sealed_grant(
            sealed(honest, stranger), session_id, challenge, phone.did, tool)),
        # A delivery captured from one review, replayed into another.
        ("replayed review", lambda: open_sealed_grant(
            sealed(honest, transcript="mds-tool-grant|other|other|grant-1||"),
            session_id, challenge, phone.did, tool)),
        # A permission for somebody else's tool, arriving correctly sealed.
        ("permission for another tool", lambda: open_sealed_grant(
            sealed(grant_for(phone, {"tool_did": stranger.did})),
            session_id, challenge, phone.did, tool)),
    ]
    ok = all([refused(name, action) for name, action in checks])

    # An acknowledgement is bound to the exact request it answers, through the
    # command's own signature — an id is chosen by the caller and repeats.
    command = ToolCommand("cmd-1", "grant-1", 1, utc_now(), "space-1", {"a": 1}, None).sign(tool)
    other = ToolCommand("cmd-1", "grant-1", 2, utc_now(), "space-1", {"a": 2}, None).sign(tool)
    answer = {"ack": {"command_id": "cmd-1", "outcome": "executed", "activity_id": "row-1"}}
    if open_sealed_ack(
        seal_envelope({**answer, "transcript": ack_transcript(command)}, phone, tool.did, tool.exchange_public_key),
        command, phone.did, tool,
    ).outcome != "executed":
        _warn("an honest acknowledgement did not open")
        return False
    ok = refused("acknowledgement for a different request", lambda: open_sealed_ack(
        seal_envelope({**answer, "transcript": ack_transcript(other)}, phone, tool.did, tool.exchange_public_key),
        command, phone.did, tool)) and ok
    ok = refused("acknowledgement from a stranger", lambda: open_sealed_ack(
        seal_envelope({**answer, "transcript": ack_transcript(command)}, stranger, tool.did, tool.exchange_public_key),
        command, phone.did, tool)) and ok

    # An invite is the one thing a person copies by hand, so what it refuses
    # decides where a mistyped one sends this tool.
    real = INVITE_SCHEME + b64url(compact_json({
        "host": "192.168.1.5", "port": 8765, "session": session_id,
        "challenge": challenge, "protocol": PROTOCOL_VERSION,
    }).encode("utf-8")).rstrip("=")
    if Invite.decode(real) is None:
        _warn("an honest invite was not read")
        return False
    for name, payload in (
        ("invite with a sixth field", {"host": "h", "port": 1, "session": "s", "challenge": "c",
                                       "protocol": PROTOCOL_VERSION, "did": "extra"}),
        ("invite naming another protocol", {"host": "h", "port": 1, "session": "s",
                                            "challenge": "c", "protocol": "mds/2"}),
        ("invite whose host hides a line break", {"host": "one\ntwo", "port": 1, "session": "s",
                                                  "challenge": "c", "protocol": PROTOCOL_VERSION}),
        ("invite with no reachable port", {"host": "h", "port": 0, "session": "s",
                                           "challenge": "c", "protocol": PROTOCOL_VERSION}),
    ):
        encoded = INVITE_SCHEME + b64url(compact_json(payload).encode("utf-8")).rstrip("=")
        if Invite.decode(encoded) is not None:
            _warn(f"an {name} was NOT refused")
            ok = False
    if Invite.decode("just some text a person pasted") is not None:
        _warn("text that is not an invite was read as one")
        ok = False
    return ok


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mds_connector.py",
        description=(
            "Carry readings from a machine into a topic on your phone. "
            "It can only do what you approve on the phone, and nothing else."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "the usual order:\n"
            "  1. profiles                        which machines it already knows\n"
            "  2. fields  --profile NAME          the topic to make in the app\n"
            "  3. preview --profile NAME          what it would add, reading nothing else\n"
            "  4. connect --profile NAME --topic ID --invite '<invite>' --every 30\n"
            "  5. run     --profile NAME --topic ID --every 30\n"
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)

    def shared(sub, needs_profile=True):
        if needs_profile:
            sub.add_argument("--profile", required=True, help="a shipped profile name, or a path to one")
        sub.add_argument("--credentials", help="file holding this machine's address and sign-in")
        return sub

    shared(commands.add_parser("profiles", help="list the machines this connector knows"), False)
    shared(commands.add_parser("fields", help="print the topic to make in the app"))

    preview = shared(commands.add_parser("preview", help="show what it would add, writing nothing"))
    preview.add_argument("--limit", type=int, help="how many records to ask the machine for")
    preview.add_argument("--since-minutes", type=int, help="how far back to ask")
    preview.add_argument("--listen-seconds", type=int, default=20, help="for machines that announce")

    def writing(sub):
        shared(sub)
        sub.add_argument("--topic", required=True, help="the topic id you granted, from the app")
        sub.add_argument("--every", type=int, help="keep carrying, this many seconds apart")
        sub.add_argument("--limit", type=int, help="how many records to ask the machine for")
        sub.add_argument("--since-minutes", type=int, help="how far back to ask")
        sub.add_argument("--state", help="where this connector keeps its key and progress")
        return sub

    connect = writing(commands.add_parser("connect", help="answer an invite from the app"))
    connect.add_argument("--invite", required=True, help="the invite you copied on the phone")
    connect.add_argument("--name", help="the name the phone shows for this tool")
    connect.add_argument("--again", action="store_true", help="connect afresh, replacing the old permission")

    run = writing(commands.add_parser("run", help="keep carrying readings"))
    run.add_argument("--host", help="only if the phone's address changed")
    run.add_argument("--port", type=int, help="only if the phone's address changed")

    commands.add_parser("check", help="prove the ciphers against their published test vectors")
    return parser


_COMMANDS = {
    "profiles": command_profiles,
    "fields": command_fields,
    "preview": command_preview,
    "connect": command_connect,
    "run": command_run,
    "check": command_check,
}


def main(argv: list[str] | None = None) -> int:
    options = build_parser().parse_args(argv)
    try:
        return _COMMANDS[options.command](options)
    except Refused as error:
        # A sentence to read, not a stack trace. Every refusal in this program
        # is something a person can act on.
        _warn(str(error))
        return 65
    except KeyboardInterrupt:
        _warn("stopped")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
