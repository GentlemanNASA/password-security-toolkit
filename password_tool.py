"""
password_tool.py
----------------
A command-line password strength checker and secure password generator.

The checker scores passwords across multiple security criteria and
displays a visual strength bar. The generator builds cryptographically
random passwords from configurable character sets.

Usage:
    python password_tool.py
"""

import secrets
import string
import re
import sys


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Minimum thresholds used by the strength checker
MIN_LENGTH_FAIR   = 8
MIN_LENGTH_GOOD   = 12
MIN_LENGTH_STRONG = 16

# Progress bar width (in characters)
BAR_WIDTH = 20

# Character pools available to the password generator
POOL_LOWERCASE = string.ascii_lowercase          # a-z
POOL_UPPERCASE = string.ascii_uppercase          # A-Z
POOL_DIGITS    = string.digits                   # 0-9
POOL_SYMBOLS   = "!@#$%^&*()-_=+[]{}|;:,.<>?"  # common special characters

# Strength labels mapped to a score out of 5
STRENGTH_LABELS = {
    0: "Very Weak",
    1: "Weak",
    2: "Fair",
    3: "Good",
    4: "Strong",
    5: "Very Strong",
}


# ---------------------------------------------------------------------------
# Password strength checker
# ---------------------------------------------------------------------------

def check_length(password: str) -> tuple[bool, str]:
    """
    Return whether the password meets the minimum recommended length and
    a human-readable note about the result.
    """
    length = len(password)
    if length >= MIN_LENGTH_STRONG:
        return True, f"Length {length} - excellent (16+ characters)"
    if length >= MIN_LENGTH_GOOD:
        return True, f"Length {length} - good (12-15 characters)"
    if length >= MIN_LENGTH_FAIR:
        return True, f"Length {length} - fair (8-11 characters)"
    return False, f"Length {length} - too short (minimum 8 characters)"


def check_uppercase(password: str) -> tuple[bool, str]:
    """Return whether the password contains at least one uppercase letter."""
    has_upper = bool(re.search(r"[A-Z]", password))
    note = "Contains uppercase letters" if has_upper else "No uppercase letters found"
    return has_upper, note


def check_lowercase(password: str) -> tuple[bool, str]:
    """Return whether the password contains at least one lowercase letter."""
    has_lower = bool(re.search(r"[a-z]", password))
    note = "Contains lowercase letters" if has_lower else "No lowercase letters found"
    return has_lower, note


def check_digits(password: str) -> tuple[bool, str]:
    """Return whether the password contains at least one digit."""
    has_digit = bool(re.search(r"\d", password))
    note = "Contains digits" if has_digit else "No digits found"
    return has_digit, note


def check_symbols(password: str) -> tuple[bool, str]:
    """Return whether the password contains at least one special character."""
    has_symbol = bool(re.search(r"[^A-Za-z0-9]", password))
    note = "Contains special characters" if has_symbol else "No special characters found"
    return has_symbol, note


def check_no_common_patterns(password: str) -> tuple[bool, str]:
    """
    Return whether the password avoids simple sequential or repeated patterns
    such as '123', 'abc', or 'aaaa'.
    """
    lower = password.lower()

    # Sequential digit runs
    for i in range(10 - 2):
        if str(i) + str(i + 1) + str(i + 2) in lower:
            return False, "Contains sequential numbers (e.g. 123)"

    # Sequential letter runs
    for i in range(ord("a"), ord("z") - 1):
        seq = chr(i) + chr(i + 1) + chr(i + 2)
        if seq in lower:
            return False, "Contains sequential letters (e.g. abc)"

    # Three or more repeated characters
    if re.search(r"(.)\1{2,}", password, re.IGNORECASE):
        return False, "Contains repeated characters (e.g. aaa)"

    return True, "No common sequential or repeated patterns detected"


# Ordered list of all checks.  Each entry is (check_function, weight).
# Weight 1 means the check contributes one point to the score out of 5.
CHECKS = [
    (check_length,             1),
    (check_uppercase,          1),
    (check_lowercase,          1),
    (check_digits,             1),
    (check_symbols,            1),
]

# Pattern check is a bonus / penalty that can modify display but is tracked
# separately so it does not inflate the core score.
PATTERN_CHECK = check_no_common_patterns


def score_password(password: str) -> dict:
    """
    Run all checks against *password* and return a results dictionary with:

        score        - integer 0-5
        label        - human-readable strength label
        checks       - list of (passed: bool, note: str) per criterion
        pattern_ok   - bool, whether pattern check passed
        pattern_note - note from the pattern check
    """
    results = []
    score = 0

    for fn, weight in CHECKS:
        passed, note = fn(password)
        results.append((passed, note))
        if passed:
            score += weight

    pattern_ok, pattern_note = PATTERN_CHECK(password)

    # Apply a one-point penalty if the password has obvious patterns,
    # but never let the score go below 0.
    if not pattern_ok and score > 0:
        score -= 1

    label = STRENGTH_LABELS.get(score, "Unknown")

    return {
        "score":        score,
        "label":        label,
        "checks":       results,
        "pattern_ok":   pattern_ok,
        "pattern_note": pattern_note,
    }


def render_strength_bar(score: int, max_score: int = 5) -> str:
    """
    Build a plain-text progress bar representing *score* out of *max_score*.

    Example output:  [################----]  4/5
    """
    filled = int(round((score / max_score) * BAR_WIDTH))
    empty  = BAR_WIDTH - filled
    bar    = "#" * filled + "-" * empty
    return f"[{bar}]  {score}/{max_score}"


def display_password_analysis(password: str) -> None:
    """Print a formatted strength report for *password*."""
    result = score_password(password)

    # Criteria labels (aligned with CHECKS order above)
    criteria_names = [
        "Length",
        "Uppercase letters",
        "Lowercase letters",
        "Digits",
        "Special characters",
    ]

    print()
    print("Password Analysis")
    print("-" * 40)

    for name, (passed, note) in zip(criteria_names, result["checks"]):
        status = "[pass]" if passed else "[fail]"
        print(f"  {status}  {name}: {note}")

    # Pattern check displayed separately
    pat_status = "[pass]" if result["pattern_ok"] else "[fail]"
    print(f"  {pat_status}  Patterns: {result['pattern_note']}")

    print()
    print(f"  Strength : {result['label']}")
    print(f"  Score    : {render_strength_bar(result['score'])}")
    print()


# ---------------------------------------------------------------------------
# Password generator
# ---------------------------------------------------------------------------

def build_character_pool(
    use_lowercase: bool = True,
    use_uppercase: bool = True,
    use_digits:    bool = True,
    use_symbols:   bool = True,
) -> str:
    """
    Combine the requested character sets into a single pool string.

    Raises ValueError if no character set is selected (an empty pool would
    make it impossible to generate a password).
    """
    pool = ""
    if use_lowercase:
        pool += POOL_LOWERCASE
    if use_uppercase:
        pool += POOL_UPPERCASE
    if use_digits:
        pool += POOL_DIGITS
    if use_symbols:
        pool += POOL_SYMBOLS

    if not pool:
        raise ValueError("At least one character set must be selected.")

    return pool


def generate_password(
    length:        int  = 16,
    use_lowercase: bool = True,
    use_uppercase: bool = True,
    use_digits:    bool = True,
    use_symbols:   bool = True,
) -> str:
    """
    Generate a cryptographically random password of *length* characters.

    The function guarantees that at least one character from each selected
    pool is present, preventing the unlikely case where the random draw
    omits an entire character class.

    Uses secrets.choice which draws from the OS-level CSPRNG — suitable
    for generating real passwords.
    """
    if length < 4:
        raise ValueError("Password length must be at least 4 characters.")

    pool = build_character_pool(use_lowercase, use_uppercase, use_digits, use_symbols)

    # Build a list of guaranteed characters — one from each active pool.
    guaranteed: list[str] = []
    if use_lowercase:
        guaranteed.append(secrets.choice(POOL_LOWERCASE))
    if use_uppercase:
        guaranteed.append(secrets.choice(POOL_UPPERCASE))
    if use_digits:
        guaranteed.append(secrets.choice(POOL_DIGITS))
    if use_symbols:
        guaranteed.append(secrets.choice(POOL_SYMBOLS))

    # Fill the remainder from the combined pool.
    remainder_length = length - len(guaranteed)
    remainder = [secrets.choice(pool) for _ in range(remainder_length)]

    # Combine and shuffle so the guaranteed characters are not always at
    # the front of the password.
    all_chars = guaranteed + remainder
    secrets.SystemRandom().shuffle(all_chars)

    return "".join(all_chars)


# ---------------------------------------------------------------------------
# Interactive CLI helpers
# ---------------------------------------------------------------------------

def prompt_yes_no(question: str, default: bool = True) -> bool:
    """
    Ask a yes/no question and return True for yes, False for no.
    The *default* value is used when the user presses Enter without input.
    """
    hint = "(Y/n)" if default else "(y/N)"
    while True:
        raw = input(f"  {question} {hint}: ").strip().lower()
        if raw == "":
            return default
        if raw in ("y", "yes"):
            return True
        if raw in ("n", "no"):
            return False
        print("  Please enter 'y' or 'n'.")


def prompt_int(question: str, min_val: int, max_val: int, default: int) -> int:
    """
    Prompt for an integer within [min_val, max_val], returning *default*
    when the user presses Enter without input.
    """
    while True:
        raw = input(f"  {question} [{min_val}-{max_val}] (default {default}): ").strip()
        if raw == "":
            return default
        try:
            value = int(raw)
        except ValueError:
            print(f"  Please enter a whole number between {min_val} and {max_val}.")
            continue
        if min_val <= value <= max_val:
            return value
        print(f"  Value must be between {min_val} and {max_val}.")


# ---------------------------------------------------------------------------
# CLI menu actions
# ---------------------------------------------------------------------------

def menu_check_password() -> None:
    """Interactively check the strength of a password supplied by the user."""
    print()
    print("Check Password Strength")
    print("-" * 40)
    password = input("  Enter a password to analyse: ")

    if not password:
        print("  No password entered.")
        return

    display_password_analysis(password)


def menu_generate_password() -> None:
    """Interactively generate one or more secure passwords."""
    print()
    print("Generate Secure Password")
    print("-" * 40)

    length      = prompt_int("Password length?", 4, 128, 16)
    use_upper   = prompt_yes_no("Include uppercase letters?",  default=True)
    use_lower   = prompt_yes_no("Include lowercase letters?",  default=True)
    use_digits  = prompt_yes_no("Include digits?",             default=True)
    use_symbols = prompt_yes_no("Include special characters?", default=True)
    count       = prompt_int("How many passwords to generate?", 1, 20, 1)

    # Make sure at least one pool is selected before we try to build a pool.
    if not any([use_upper, use_lower, use_digits, use_symbols]):
        print("\n  [fail] You must select at least one character type.")
        return

    print()
    print(f"  Generated password{'s' if count > 1 else ''}:")
    print()

    for i in range(1, count + 1):
        pwd = generate_password(
            length        = length,
            use_lowercase = use_lower,
            use_uppercase = use_upper,
            use_digits    = use_digits,
            use_symbols   = use_symbols,
        )
        prefix = f"  {i:>2}. " if count > 1 else "  "
        print(f"{prefix}{pwd}")

        # Show a quick inline strength summary for each generated password.
        result = score_password(pwd)
        bar    = render_strength_bar(result["score"])
        print(f"       Strength: {result['label']} {bar}")
        print()


def menu_about() -> None:
    """Display a brief explanation of the scoring criteria."""
    print()
    print("About This Tool")
    print("-" * 40)
    print(
        "  Password strength is scored across five criteria (one point each):\n"
        "\n"
        "  1. Length         - 8 or more characters\n"
        "  2. Uppercase      - at least one A-Z character\n"
        "  3. Lowercase      - at least one a-z character\n"
        "  4. Digits         - at least one 0-9 character\n"
        "  5. Special chars  - at least one symbol (e.g. !@#$)\n"
        "\n"
        "  A one-point penalty is applied when obvious patterns are detected\n"
        "  (sequential runs like '123' or 'abc', or repeated chars like 'aaa').\n"
        "\n"
        "  Passwords are generated using Python's 'secrets' module, which draws\n"
        "  from the OS cryptographically secure pseudo-random number generator\n"
        "  (CSPRNG). This makes generated passwords suitable for real use.\n"
    )


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

MENU = """
Password Security Toolkit
--------------------------
  1. Check password strength
  2. Generate a secure password
  3. About / scoring criteria
  4. Exit
"""


def main() -> None:
    """Run the interactive CLI menu loop."""
    print("\nWelcome to the Password Security Toolkit")

    while True:
        print(MENU)
        choice = input("Select an option (1-4): ").strip()

        if choice == "1":
            menu_check_password()
        elif choice == "2":
            menu_generate_password()
        elif choice == "3":
            menu_about()
        elif choice == "4":
            print("\nGoodbye.\n")
            sys.exit(0)
        else:
            print("  Invalid option. Please enter a number from 1 to 4.")


if __name__ == "__main__":
    main()
