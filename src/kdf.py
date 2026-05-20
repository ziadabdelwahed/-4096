import hashlib
import hmac

from typing import Tuple

from src.spec import (
    PBKDF2_ITERATIONS,
    PBKDF2_SALT_PREFIX,
    HMAC_KEY,
    SECP256K1_ORDER
)


def mnemonic_to_seed(
    mnemonic: str,
    passphrase: str = ""
) -> bytes:

    salt = (
        PBKDF2_SALT_PREFIX
        + passphrase
    ).encode('utf-8')

    return hashlib.pbkdf2_hmac(
        'sha512',
        mnemonic.encode('utf-8'),
        salt,
        PBKDF2_ITERATIONS,
        64
    )


def seed_to_root_material(
    seed: bytes
) -> Tuple[bytes, bytes]:

    h = hmac.new(
        HMAC_KEY,
        seed,
        hashlib.sha512
    ).digest()

    il, ir = h[:32], h[32:]

    il_int = int.from_bytes(il, 'big')

    if (
        il_int == 0
        or il_int >= SECP256K1_ORDER
    ):
        raise ValueError(
            "IL out of secp256k1 range"
        )

    return il, ir
