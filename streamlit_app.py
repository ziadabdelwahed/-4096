import streamlit as st
import secrets

from src.encoding import (
    entropy_to_mnemonic,
    mnemonic_to_entropy
)

from src.validation import validate_mnemonic

from src.kdf import (
    mnemonic_to_seed,
    seed_to_root_material
)

from src.spec import (
    VALID_ENTROPY_SIZES,
    ENTROPY_TO_WORDS
)


def load_wordlist():
    with open(
        "wordlist/z4096_english.txt",
        'r',
        encoding='utf-8'
    ) as f:
        return [
            line.strip()
            for line in f
            if line.strip()
        ]


st.set_page_config(
    page_title="Z-4096 Protocol",
    page_icon="🔐",
    layout="wide"
)

st.title("🔐 Z-4096 Protocol")

st.subheader(
    "Mnemonic Encoding Scheme · Deterministic · Reversible · Tagged"
)

st.caption(
    "encode() + decode() + validate()"
)

wl = load_wordlist()

st.info(
    f"Dictionary: {len(wl)} words · "
    f"Valid entropy sizes: "
    f"{sorted(VALID_ENTROPY_SIZES)} bits"
)

st.markdown("---")

col1, col2, col3 = st.columns(3)

with col1:

    st.subheader("Generate")

    ent_choice = st.selectbox(
        "Entropy size:",
        sorted(VALID_ENTROPY_SIZES)
    )

    expected_words = ENTROPY_TO_WORDS[ent_choice]

    st.caption(
        f"Produces {expected_words} words"
    )

    if st.button(
        "Generate",
        type="primary",
        use_container_width=True
    ):

        entropy = secrets.token_bytes(
            ent_choice // 8
        )

        mnemonic = entropy_to_mnemonic(
            entropy,
            wl
        )

        seed = mnemonic_to_seed(mnemonic)

        try:
            il, ir = seed_to_root_material(seed)
            il_ok = True

        except ValueError:
            il = b'\x00' * 32
            ir = b'\x00' * 32
            il_ok = False

        st.session_state['mnemonic'] = mnemonic
        st.session_state['entropy_hex'] = entropy.hex()
        st.session_state['seed'] = seed.hex()
        st.session_state['il'] = il.hex()
        st.session_state['ir'] = ir.hex()
        st.session_state['il_ok'] = il_ok
        st.session_state['ent_bits'] = ent_choice
        st.session_state['wc'] = expected_words

    if 'mnemonic' in st.session_state:

        st.markdown("---")

        st.code(
            st.session_state['mnemonic']
        )

        c1, c2 = st.columns(2)

        c1.metric(
            "Words",
            st.session_state['wc']
        )

        c2.metric(
            "Entropy",
            f"{st.session_state['ent_bits']} bits"
        )

        st.caption(
            f"Search space: "
            f"2^{st.session_state['ent_bits']}"
        )

with col2:

    st.subheader("Decode")

    phrase = st.text_area(
        "Enter phrase:",
        height=100,
        placeholder="word1 word2 ...",
        key="decode_phrase"
    )

    if st.button(
        "Decode",
        use_container_width=True
    ):

        if phrase.strip():

            entropy = mnemonic_to_entropy(
                phrase.strip(),
                wl
            )

            if entropy:

                st.success(
                    "Valid phrase"
                )

                st.text(
                    f"Entropy: {entropy.hex()}"
                )

                st.text(
                    f"Length: "
                    f"{len(entropy) * 8} bits"
                )

            else:
                st.error(
                    "Invalid phrase"
                )

        else:
            st.warning(
                "Enter a phrase"
            )

with col3:

    st.subheader("Recover")

    phrase2 = st.text_area(
        "Enter phrase:",
        height=100,
        placeholder="word1 word2 ...",
        key="recover_phrase"
    )

    if st.button(
        "Recover",
        use_container_width=True
    ):

        if phrase2.strip():

            if validate_mnemonic(
                phrase2.strip(),
                wl
            ):

                seed = mnemonic_to_seed(
                    phrase2.strip()
                )

                try:
                    il, ir = seed_to_root_material(seed)

                    st.success(
                        "Valid phrase"
                    )

                    st.text(
                        f"Seed: "
                        f"{seed.hex()[:32]}..."
                    )

                    st.text(
                        f"IL: "
                        f"{il.hex()[:32]}..."
                    )

                    st.text(
                        f"IR: "
                        f"{ir.hex()[:32]}..."
                    )

                except ValueError:
                    st.error(
                        "IL out of secp256k1 range"
                    )

            else:
                st.error(
                    "Invalid phrase"
                )

        else:
            st.warning(
                "Enter a phrase"
            )

st.markdown("---")

st.warning(
    "Z-4096 is a mnemonic encoding scheme. "
    "This is not a production wallet protocol."
)

st.caption(
    "Z-4096 Protocol v2.2"
      )
