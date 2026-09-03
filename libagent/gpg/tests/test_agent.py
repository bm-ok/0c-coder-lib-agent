import binascii
import hashlib
import types

import ecdsa
import pytest

from ... import formats, util
from .. import agent, client, keyring, protocol


def test_sig_encode():
    SIG = (
        b'(7:sig-val(5:ecdsa(1:r32:\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x0c)(1:s32:\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00")))')
    assert agent.sig_encode(12, 34) == SIG


CREATED = 1500000000  # arbitrary, fixed so that key IDs are reproducible
USER_ID_FIRST = 'First User <first@example.com>'
USER_ID_SECOND = 'Second User <second@example.com>'
USER_ID_OTHER = 'Nobody <nobody@example.com>'


def _derive(identity):
    """Derive a distinct NIST256 key per identity, the way a device would."""
    # The device hashes Identity.to_bytes() - which does NOT include the
    # keygrip - so the user ID alone decides which key comes back.
    secexp = util.bytes2num(hashlib.sha256(identity.to_bytes()).digest())
    return ecdsa.SigningKey.from_secret_exponent(
        secexp=secexp, curve=ecdsa.curves.NIST256p,
        hashfunc=hashlib.sha256).get_verifying_key()


class FakeDevice:
    """Device that derives keys in-process, without any hardware."""

    def __init__(self):
        """C-tor."""
        self.ui = types.SimpleNamespace(options_getter=None)
        self.user_ids = []

    def __enter__(self):
        """Allow usage as context manager."""
        return self

    def __exit__(self, *args):
        """Nothing to close."""

    def pubkey(self, identity, ecdh=False):  # pylint: disable=unused-argument
        """Return the public key derived for this identity."""
        self.user_ids.append(identity.identity_dict['host'])
        return _derive(identity)


def _public_key_blob(derived_from, user_ids):
    """Serialize a public key packet, followed by several user ID packets."""
    identity = client.create_identity(user_id=derived_from,
                                      curve_name=formats.CURVE_NIST256)
    pubkey = protocol.PublicKey(curve_name=formats.CURVE_NIST256,
                                created=CREATED,
                                verifying_key=_derive(identity))
    blob = protocol.packet(tag=6, blob=pubkey.data())
    for user_id in user_ids:
        blob += protocol.packet(tag=13, blob=user_id.encode('utf-8'))
    return binascii.hexlify(pubkey.keygrip()).upper(), blob


def _handler(monkeypatch, pubkey_bytes):
    monkeypatch.setattr(keyring, 'gpg_version', lambda: b'2.2.0')
    return agent.Handler(device=FakeDevice(), pubkey_bytes=pubkey_bytes)


def test_get_identity_uses_user_id_matching_keygrip(monkeypatch):
    # The key belongs to the SECOND user ID of a two-user-ID public key.
    keygrip, pubkey_bytes = _public_key_blob(
        derived_from=USER_ID_SECOND,
        user_ids=[USER_ID_FIRST, USER_ID_SECOND])
    handler = _handler(monkeypatch, pubkey_bytes)
    identity = handler.get_identity(keygrip=keygrip)
    assert identity.identity_dict['host'] == USER_ID_SECOND
    assert handler.client.device.user_ids == [USER_ID_FIRST, USER_ID_SECOND]


def test_get_identity_without_matching_user_id(monkeypatch):
    # No user ID of the key re-derives it, so the keygrip must be reported as
    # missing (KeyError) - which is what have_key() and GnuPG can act upon.
    keygrip, pubkey_bytes = _public_key_blob(
        derived_from=USER_ID_OTHER,
        user_ids=[USER_ID_FIRST, USER_ID_SECOND])
    handler = _handler(monkeypatch, pubkey_bytes)
    with pytest.raises(KeyError):
        handler.get_identity(keygrip=keygrip)
