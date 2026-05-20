from typing import Set

VALID_ENTROPY_SIZES: Set[int] = {128, 160, 192, 224, 256}

BITS_PER_WORD: int = 12
WORDLIST_SIZE: int = 4096

DOMAIN_TAG: bytes = b"Z4096_ALIGN_V1"

PBKDF2_ITERATIONS: int = 2048
PBKDF2_SALT_PREFIX: str = "mnemonic"

HMAC_KEY: bytes = b"Bitcoin seed"

SECP256K1_ORDER: int = (
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
)

ALLOWED_WORD_COUNTS: Set[int] = {12, 15, 18, 21, 24}

ENTROPY_TO_WORDS = {
    128: 12,
    160: 15,
    192: 18,
    224: 21,
    256: 24,
}

WORDS_TO_ENTROPY = {
    12: 128,
    15: 160,
    18: 192,
    21: 224,
    24: 256,
}


def extract_bits(data: bytes, num_bits: int) -> int:
    byte_count = (num_bits + 7) // 8

    value = int.from_bytes(data[:byte_count], 'big')

    excess = (byte_count * 8) - num_bits

    if excess > 0:
        value = value >> excess

    return value


def bits_to_bytes(value: int, num_bits: int) -> bytes:
    byte_count = (num_bits + 7) // 8
    return value.to_bytes(byte_count, 'big')
