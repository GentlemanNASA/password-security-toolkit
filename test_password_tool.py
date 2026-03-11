"""
test_password_tool.py
---------------------
Unit tests for password_tool.py.

Run with:
    pytest test_password_tool.py -v
"""

import re
import pytest

from password_tool import (
    # Checker functions
    check_length,
    check_uppercase,
    check_lowercase,
    check_digits,
    check_symbols,
    check_no_common_patterns,
    score_password,
    render_strength_bar,

    # Generator functions
    build_character_pool,
    generate_password,

    # Constants
    POOL_LOWERCASE,
    POOL_UPPERCASE,
    POOL_DIGITS,
    POOL_SYMBOLS,
    BAR_WIDTH,
)


# ---------------------------------------------------------------------------
# check_length
# ---------------------------------------------------------------------------

class TestCheckLength:
    def test_very_short_password_fails(self):
        passed, note = check_length("abc")
        assert passed is False
        assert "too short" in note.lower()

    def test_exactly_minimum_length_passes(self):
        passed, _ = check_length("a" * 8)
        assert passed is True

    def test_good_length_passes(self):
        passed, note = check_length("a" * 12)
        assert passed is True
        assert "good" in note.lower()

    def test_excellent_length_passes(self):
        passed, note = check_length("a" * 16)
        assert passed is True
        assert "excellent" in note.lower()

    def test_empty_password_fails(self):
        passed, _ = check_length("")
        assert passed is False


# ---------------------------------------------------------------------------
# check_uppercase
# ---------------------------------------------------------------------------

class TestCheckUppercase:
    def test_has_uppercase(self):
        passed, note = check_uppercase("helloWorld")
        assert passed is True
        assert "uppercase" in note.lower()

    def test_no_uppercase(self):
        passed, note = check_uppercase("helloworld")
        assert passed is False
        assert "no uppercase" in note.lower()

    def test_all_uppercase(self):
        passed, _ = check_uppercase("HELLO")
        assert passed is True

    def test_single_uppercase(self):
        passed, _ = check_uppercase("A")
        assert passed is True


# ---------------------------------------------------------------------------
# check_lowercase
# ---------------------------------------------------------------------------

class TestCheckLowercase:
    def test_has_lowercase(self):
        passed, _ = check_lowercase("HELLOworld")
        assert passed is True

    def test_no_lowercase(self):
        passed, note = check_lowercase("HELLO123")
        assert passed is False
        assert "no lowercase" in note.lower()

    def test_single_lowercase(self):
        passed, _ = check_lowercase("a")
        assert passed is True


# ---------------------------------------------------------------------------
# check_digits
# ---------------------------------------------------------------------------

class TestCheckDigits:
    def test_has_digit(self):
        passed, _ = check_digits("password1")
        assert passed is True

    def test_no_digit(self):
        passed, note = check_digits("passwordABC")
        assert passed is False
        assert "no digits" in note.lower()

    def test_all_digits(self):
        passed, _ = check_digits("123456")
        assert passed is True


# ---------------------------------------------------------------------------
# check_symbols
# ---------------------------------------------------------------------------

class TestCheckSymbols:
    def test_has_symbol(self):
        passed, _ = check_symbols("password!")
        assert passed is True

    def test_no_symbol(self):
        passed, note = check_symbols("Password1")
        assert passed is False
        assert "no special" in note.lower()

    def test_various_symbols(self):
        for sym in "!@#$%^&*()":
            passed, _ = check_symbols(f"abc{sym}")
            assert passed is True, f"Expected symbol '{sym}' to be detected"


# ---------------------------------------------------------------------------
# check_no_common_patterns
# ---------------------------------------------------------------------------

class TestCheckNoCommonPatterns:
    def test_clean_password_passes(self):
        passed, _ = check_no_common_patterns("Tr0ub4dor&3")
        assert passed is True

    def test_sequential_numbers_fail(self):
        passed, note = check_no_common_patterns("pass123word")
        assert passed is False
        assert "sequential" in note.lower()

    def test_sequential_letters_fail(self):
        passed, note = check_no_common_patterns("abcPassword1!")
        assert passed is False
        assert "sequential" in note.lower()

    def test_repeated_characters_fail(self):
        passed, note = check_no_common_patterns("paaaassword")
        assert passed is False
        assert "repeated" in note.lower()

    def test_case_insensitive_sequential_detection(self):
        # 'ABC' should be caught as sequential letters regardless of case
        passed, _ = check_no_common_patterns("ABCPassword1!")
        assert passed is False


# ---------------------------------------------------------------------------
# score_password
# ---------------------------------------------------------------------------

class TestScorePassword:
    def test_very_weak_password_score_is_low(self):
        result = score_password("abc")
        assert result["score"] <= 2

    def test_strong_password_scores_high(self):
        # A well-crafted password should score 4 or 5
        result = score_password("Tr0ub4dor&3!XyZq")
        assert result["score"] >= 4

    def test_result_contains_expected_keys(self):
        result = score_password("Test1234!")
        for key in ("score", "label", "checks", "pattern_ok", "pattern_note"):
            assert key in result, f"Expected key '{key}' missing from result"

    def test_score_bounded_between_0_and_5(self):
        for pwd in ["", "a", "aaaaaa", "A1!bCdEfGhIj", "Aa1!Aa1!Aa1!Aa1!"]:
            result = score_password(pwd)
            assert 0 <= result["score"] <= 5, (
                f"Score {result['score']} out of range for password '{pwd}'"
            )

    def test_label_is_non_empty_string(self):
        result = score_password("SomePassword1!")
        assert isinstance(result["label"], str)
        assert len(result["label"]) > 0

    def test_pattern_penalty_reduces_score(self):
        # Password with all character types but a sequential pattern
        result_clean   = score_password("Tr0ub4dor&3!XyZq")
        result_pattern = score_password("Tr0ub4dor123!XyZ")
        # Pattern version should score equal or lower
        assert result_pattern["score"] <= result_clean["score"]


# ---------------------------------------------------------------------------
# render_strength_bar
# ---------------------------------------------------------------------------

class TestRenderStrengthBar:
    def test_bar_contains_brackets(self):
        bar = render_strength_bar(3)
        assert bar.startswith("[")
        assert "]" in bar

    def test_bar_width_is_correct(self):
        bar = render_strength_bar(3)
        # Extract content between the brackets
        inner = bar.split("[")[1].split("]")[0]
        assert len(inner) == BAR_WIDTH

    def test_full_score_bar_is_all_hashes(self):
        bar = render_strength_bar(5, max_score=5)
        inner = bar.split("[")[1].split("]")[0]
        assert inner == "#" * BAR_WIDTH

    def test_zero_score_bar_is_all_dashes(self):
        bar = render_strength_bar(0, max_score=5)
        inner = bar.split("[")[1].split("]")[0]
        assert inner == "-" * BAR_WIDTH

    def test_bar_contains_score_fraction(self):
        bar = render_strength_bar(3, max_score=5)
        assert "3/5" in bar


# ---------------------------------------------------------------------------
# build_character_pool
# ---------------------------------------------------------------------------

class TestBuildCharacterPool:
    def test_all_pools_enabled(self):
        pool = build_character_pool(True, True, True, True)
        # Every pool must be represented
        assert any(c in pool for c in POOL_LOWERCASE)
        assert any(c in pool for c in POOL_UPPERCASE)
        assert any(c in pool for c in POOL_DIGITS)
        assert any(c in pool for c in POOL_SYMBOLS)

    def test_only_digits(self):
        pool = build_character_pool(False, False, True, False)
        assert pool == POOL_DIGITS

    def test_empty_pool_raises(self):
        with pytest.raises(ValueError, match="At least one"):
            build_character_pool(False, False, False, False)

    def test_pool_contains_no_duplicates_per_set(self):
        # Individual constant pools should have unique characters
        for pool in (POOL_LOWERCASE, POOL_UPPERCASE, POOL_DIGITS):
            assert len(pool) == len(set(pool))


# ---------------------------------------------------------------------------
# generate_password
# ---------------------------------------------------------------------------

class TestGeneratePassword:
    def test_output_length_is_correct(self):
        for length in (8, 12, 16, 32, 64):
            pwd = generate_password(length=length)
            assert len(pwd) == length, f"Expected length {length}, got {len(pwd)}"

    def test_generated_password_contains_all_character_types(self):
        # With all pools enabled and a long password the chance of missing a
        # character type is astronomically small; we treat a failure as a bug.
        pwd = generate_password(length=32)
        assert re.search(r"[a-z]", pwd), "No lowercase in generated password"
        assert re.search(r"[A-Z]", pwd), "No uppercase in generated password"
        assert re.search(r"\d",    pwd), "No digit in generated password"
        assert re.search(r"[^A-Za-z0-9]", pwd), "No symbol in generated password"

    def test_only_digits_pool(self):
        pwd = generate_password(
            length=20,
            use_lowercase=False,
            use_uppercase=False,
            use_digits=True,
            use_symbols=False,
        )
        assert pwd.isdigit()

    def test_only_lowercase_pool(self):
        pwd = generate_password(
            length=20,
            use_lowercase=True,
            use_uppercase=False,
            use_digits=False,
            use_symbols=False,
        )
        assert pwd.isalpha()
        assert pwd == pwd.lower()

    def test_minimum_length_boundary(self):
        pwd = generate_password(length=4)
        assert len(pwd) == 4

    def test_length_too_short_raises(self):
        with pytest.raises(ValueError):
            generate_password(length=3)

    def test_passwords_are_not_all_identical(self):
        # Two independently generated passwords should almost never be equal
        passwords = {generate_password(length=16) for _ in range(10)}
        assert len(passwords) > 1, "All generated passwords were identical"

    def test_no_character_type_selected_raises(self):
        with pytest.raises(ValueError):
            generate_password(
                length=16,
                use_lowercase=False,
                use_uppercase=False,
                use_digits=False,
                use_symbols=False,
            )

    def test_long_password_generation(self):
        pwd = generate_password(length=128)
        assert len(pwd) == 128
