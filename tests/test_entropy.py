import math
import re

from secret_finder.entropy import (
    ENTROPY_MIN_LENGTH,
    ENTROPY_THRESHOLD,
    charset_normalized_entropy,
    extract_candidates,
    is_allowlisted,
    shannon_entropy,
)


def test_thresholds_are_defaults():
    assert ENTROPY_THRESHOLD == 4.5
    assert ENTROPY_MIN_LENGTH == 16


def test_shannon_known_values():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert math.isclose(shannon_entropy("ab"), 1.0)
    assert math.isclose(shannon_entropy("abcd"), 2.0)


def test_shannon_high_entropy_string_exceeds_threshold():
    # 32 distinct chars → H = log2(32) = 5.0 > 4.5
    s = "abcdefghijklmnopqrstuvwxyzABCDEF"
    assert shannon_entropy(s) > ENTROPY_THRESHOLD


def test_charset_normalized_bounds():
    assert charset_normalized_entropy("") == 0.0
    assert charset_normalized_entropy("a") == 0.0
    assert charset_normalized_entropy("aaaa") == 0.0
    # balanced 2-char alphabet → H = 1, log2(2) = 1 → 1.0
    assert math.isclose(charset_normalized_entropy("abab"), 1.0)
    # never exceeds 1.0
    assert charset_normalized_entropy("abcdefg") <= 1.0


def test_extract_finds_base64_and_hex():
    content = 'key = "dGVzdGluZ19iYXNlNjRfdG9rZW5fMQ==" and deadbeefdeadbeefcafe'
    cands = extract_candidates(content)
    assert "dGVzdGluZ19iYXNlNjRfdG9rZW5fMQ" in cands
    assert "deadbeefdeadbeefcafe" in cands


def test_extract_strips_quotes_and_padding():
    content = "'QUJDREVGR0hJSktMTU5PUA===='"
    assert extract_candidates(content) == ["QUJDREVGR0hJSktMTU5PUA"]


def test_extract_skips_short_and_dedupes():
    content = (
        "short abc123 too_short_16chars x "
        + "A1b2C3d4E5f6G7h8I9j0 "
        + "A1b2C3d4E5f6G7h8I9j0"
    )
    cands = extract_candidates(content)
    assert all(len(c) >= ENTROPY_MIN_LENGTH for c in cands)
    assert len(cands) == len(set(cands))


def test_is_allowlisted_matches_hash_and_uuid():
    patterns = [
        re.compile(r"[0-9a-f]{40}"),
        re.compile(r"[0-9a-f]{64}"),
        re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
    ]
    sha1 = "a" * 40
    sha256 = "b" * 64
    uuid = "123e4567-e89b-12d3-a456-426614174000"
    assert is_allowlisted(sha1, patterns)
    assert is_allowlisted(sha256, patterns)
    assert is_allowlisted(uuid, patterns)
    assert not is_allowlisted("dGVzdGluZ19iYXNlNjRfdG9rZW5fMQ", patterns)
    assert not is_allowlisted("zzz", patterns)
