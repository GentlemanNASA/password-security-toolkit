# Password Security Toolkit

A command-line Python tool for checking password strength and generating cryptographically secure passwords. Built as a practical introduction to password security concepts.

---

## Preview

```
Password Analysis
----------------------------------------
  [pass]  Length: Length 17 - excellent (16+ characters)
  [pass]  Uppercase letters: Contains uppercase letters
  [pass]  Lowercase letters: Contains lowercase letters
  [pass]  Digits: Contains digits
  [pass]  Special characters: Contains special characters
  [pass]  Patterns: No common sequential or repeated patterns detected

  Strength : Very Strong
  Score    : [####################]  5/5
```

```
Generated passwords:

   1. mK$9vR!zLp#2Xw&Q
        Strength: Very Strong [####################]  5/5

   2. Tz&8nJ!cWq#5Ys@M
        Strength: Very Strong [####################]  5/5
```

---

## Features

| Feature | Details |
|---|---|
| Strength checker | Scores passwords across 5 security criteria |
| Visual score bar | Plain `#` / `-` progress bar, no dependencies |
| Pattern detection | Flags sequential runs (`123`, `abc`) and repeated chars (`aaa`) |
| Secure generator | Uses Python `secrets` module (OS-level CSPRNG) |
| Character pools | Lowercase, uppercase, digits, symbols — all configurable |
| Guaranteed coverage | Every selected character type is always present in output |
| Batch generation | Generate up to 20 passwords in one run |
| Unit tests | Full pytest suite covering checker and generator |

---

## Requirements

- Python 3.10 or later (uses `tuple[bool, str]` type hints)
- No third-party packages required for `password_tool.py`
- `pytest` is required to run the tests

Install pytest if needed:

```bash
pip install pytest
```

---

## Usage

### Run the interactive menu

```bash
python password_tool.py
```

You will see a menu with four options:

```
Password Security Toolkit
--------------------------
  1. Check password strength
  2. Generate a secure password
  3. About / scoring criteria
  4. Exit
```

### Check a password

Select option 1, enter your password, and the tool prints a full breakdown of which criteria passed or failed alongside a strength bar.

### Generate a password

Select option 2 and answer the prompts:

- Password length (4-128, default 16)
- Whether to include uppercase, lowercase, digits, and symbols
- How many passwords to generate (1-20)

Each generated password is immediately scored so you can see its strength at a glance.

### Run the unit tests

```bash
pytest test_password_tool.py -v
```

Expected output: all tests passing. The suite covers boundary conditions, pattern detection, character pool validation, and the generator's cryptographic guarantees.

---

## Scoring Criteria

Each of the five criteria below contributes one point to the score (maximum 5):

| Criterion | Requirement |
|---|---|
| Length | 8 or more characters |
| Uppercase | At least one A-Z character |
| Lowercase | At least one a-z character |
| Digits | At least one 0-9 character |
| Special characters | At least one symbol (e.g. `!@#$`) |

A one-point penalty is applied when obvious patterns are detected (sequential runs like `123` or `abc`, or three or more repeated characters like `aaa`). The score never drops below 0.

| Score | Label |
|---|---|
| 0 | Very Weak |
| 1 | Weak |
| 2 | Fair |
| 3 | Good |
| 4 | Strong |
| 5 | Very Strong |

---

## Cybersecurity Concepts Covered

**Entropy and length** — Every additional character multiplies the search space an attacker must cover. A 16-character password from a 95-character printable ASCII set has roughly 10^31 combinations, compared to ~10^11 for an 8-character lowercase-only password.

**Character diversity** — Mixing lowercase, uppercase, digits, and symbols forces brute-force tools to use a larger character set, increasing the time required to crack the password even at the same length.

**Pattern avoidance** — Common patterns like `123`, `abc`, or `aaaa` appear in leaked password databases and in the rules of password cracking tools such as Hashcat. A password that contains these patterns is vulnerable even if it meets length and diversity requirements.

**Cryptographically secure random number generation** — Python's `random` module uses a Mersenne Twister, which is not cryptographically secure — its state can be reconstructed from observed outputs. The `secrets` module draws directly from the operating system's CSPRNG (`/dev/urandom` on Linux/macOS, `CryptGenRandom` on Windows), making the output unpredictable to an attacker who has observed previous outputs.

**Defense in depth** — No single criterion is sufficient on its own. A long password composed entirely of one character type is weak. A short password with all character types is also weak. Strong passwords satisfy all criteria simultaneously.

---

## Project Structure

```
password-security-toolkit/
    password_tool.py        # Strength checker and password generator
    test_password_tool.py   # pytest unit tests
    README.md               # This file
```

---

## License

MIT License. Use freely for learning, personal projects, and security education.
