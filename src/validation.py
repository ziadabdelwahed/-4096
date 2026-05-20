from typing import List

from src.encoding import mnemonic_to_entropy

from src.spec import ALLOWED_WORD_COUNTS


def validate_mnemonic(
    mnemonic: str,
    wordlist: List[str]
) -> bool:

    words = mnemonic.strip().split()

    if len(words) not in ALLOWED_WORD_COUNTS:
        return False

    if any(w not in wordlist for w in words):
        return False

    entropy = mnemonic_to_entropy(
        mnemonic,
        wordlist
    )

    return entropy is not None
