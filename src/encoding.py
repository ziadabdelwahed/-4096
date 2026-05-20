import hashlib

from typing import List, Optional

from src.spec import (
    VALID_ENTROPY_SIZES,
    BITS_PER_WORD,
    WORDLIST_SIZE,
    DOMAIN_TAG,
    ALLOWED_WORD_COUNTS,
    WORDS_TO_ENTROPY,
    extract_bits
)


def entropy_to_mnemonic(entropy: bytes, wordlist: List[str]) -> str:
    ENT = len(entropy) * 8

    if ENT not in VALID_ENTROPY_SIZES:
        raise ValueError(
            f"Entropy must be one of {VALID_ENTROPY_SIZES} bits, got {ENT}"
        )

    CS = ENT // 32

    h = hashlib.sha256(entropy).digest()

    checksum = extract_bits(h, CS)

    entropy_int = int.from_bytes(entropy, 'big')

    combined = (entropy_int << CS) | checksum

    used_bits = ENT + CS

    target_bits = (
        (used_bits + BITS_PER_WORD - 1)
        // BITS_PER_WORD
    ) * BITS_PER_WORD

    PAD = target_bits - used_bits

    if PAD > 0:
        combined_bytes = combined.to_bytes(
            (used_bits + 7) // 8,
            'big'
        )

        pre_hash = DOMAIN_TAG + combined_bytes

        ah = hashlib.sha256(pre_hash).digest()

        pad_val = extract_bits(ah, PAD)

        combined = (combined << PAD) | pad_val

        used_bits = target_bits

    word_count = used_bits // BITS_PER_WORD

    words = []

    for i in range(word_count):
        shift = used_bits - BITS_PER_WORD * (i + 1)

        index = (
            (combined >> shift)
            & (WORDLIST_SIZE - 1)
        )

        words.append(wordlist[index])

    return ' '.join(words)


def mnemonic_to_entropy(
    mnemonic: str,
    wordlist: List[str]
) -> Optional[bytes]:

    words = mnemonic.strip().split()

    if len(words) not in ALLOWED_WORD_COUNTS:
        return None

    if any(w not in wordlist for w in words):
        return None

    indices = [wordlist.index(w) for w in words]

    combined = 0

    for idx in indices:
        combined = (
            (combined << BITS_PER_WORD)
            | idx
        )

    word_count = len(words)

    if word_count not in WORDS_TO_ENTROPY:
        return None

    ENT = WORDS_TO_ENTROPY[word_count]

    CS = ENT // 32

    used_bits = ENT + CS

    target_bits = (
        (used_bits + BITS_PER_WORD - 1)
        // BITS_PER_WORD
    ) * BITS_PER_WORD

    PAD = target_bits - used_bits

    if PAD > 0:
        extracted_pad = combined & ((1 << PAD) - 1)

        combined = combined >> PAD
    else:
        extracted_pad = None

    checksum = combined & ((1 << CS) - 1)

    entropy_int = combined >> CS

    try:
        entropy_bytes = entropy_int.to_bytes(
            ENT // 8,
            'big'
        )
    except OverflowError:
        return None

    h = hashlib.sha256(entropy_bytes).digest()

    expected_checksum = extract_bits(h, CS)

    if checksum != expected_checksum:
        return None

    if PAD > 0 and extracted_pad is not None:
        combined_no_pad = (
            (entropy_int << CS)
            | checksum
        )

        combined_bytes = combined_no_pad.to_bytes(
            (used_bits + 7) // 8,
            'big'
        )

        pre_hash = DOMAIN_TAG + combined_bytes

        ah = hashlib.sha256(pre_hash).digest()

        expected_pad = extract_bits(ah, PAD)

        if extracted_pad != expected_pad:
            return None

    return entropy_bytes
