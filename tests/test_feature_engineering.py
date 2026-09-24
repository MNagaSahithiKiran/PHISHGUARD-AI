import sys
from pathlib import Path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest
from ml.feature_engineering.url_features import extract_url_feature_vector
from ml.feature_engineering.lexical_features import (
    calculate_shannon_entropy,
    calculate_repeated_char_max,
    count_special_characters,
    calculate_char_ratios
)


def test_standard_url_features():
    url = "https://www.example.com/path/to/page.html?query=val&ref=test#section"
    feats = extract_url_feature_vector(url)
    assert feats["url_length"] == len(url)
    assert feats["count_dots"] >= 2
    assert feats["count_slashes"] >= 4
    assert feats["has_https"] == 1
    assert feats["has_ip_address"] == 0
    assert feats["url_entropy"] > 0
    assert feats["query_param_count"] == 2
    assert feats["path_token_count"] == 3


def test_ip_address_url():
    url = "http://198.51.100.4/secure/login"
    feats = extract_url_feature_vector(url)
    assert feats["has_ip_address"] == 1
    assert feats["has_https"] == 0
    assert feats["path_token_count"] == 2


def test_authentication_syntax_url():
    url = "https://legit-service.com@malicious-harvest.xyz/account/login"
    feats = extract_url_feature_vector(url)
    assert feats["has_at_symbol"] == 1
    assert feats["count_at_symbol"] if "count_at_symbol" in feats else True
    assert feats["suspicious_keyword_count"] >= 2  # account, login


def test_unicode_punycode_domain():
    url = "https://xn--e1afmkfd.xn--p1ai/auth"
    feats = extract_url_feature_vector(url)
    assert feats["has_punycode"] == 1


def test_extremely_long_url():
    long_path = "a" * 2500
    url = f"https://example.com/{long_path}"
    feats = extract_url_feature_vector(url)
    assert feats["url_length"] > 2500
    assert feats["repeated_char_max"] >= 2500


def test_empty_and_malformed_url():
    feats_empty = extract_url_feature_vector("")
    assert isinstance(feats_empty, dict)
    assert feats_empty["url_length"] == 0

    feats_invalid = extract_url_feature_vector("not a valid url :///")
    assert isinstance(feats_invalid, dict)


def test_shannon_entropy_calculation():
    # Constant string has 0 entropy
    assert calculate_shannon_entropy("aaaaaaaa") == 0.0
    # Random diverse string has high entropy
    entropy_diverse = calculate_shannon_entropy("a1b2c3d4e5f6!@#$")
    assert entropy_diverse > 3.0


def test_repeated_char_calculation():
    assert calculate_repeated_char_max("abc") == 1
    assert calculate_repeated_char_max("abbbcde") == 3
    assert calculate_repeated_char_max("goooooogle") == 6


def test_special_character_counting():
    assert count_special_characters("test!@#$") == 4
    digits, specials = calculate_char_ratios("abc123!@#")
    assert digits == round(3 / 9, 4)
    assert specials == round(3 / 9, 4)
