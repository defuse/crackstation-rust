# crackstation-rust

A Rust rewrite of [crackstation.net](https://crackstation.net/), ported from the original PHP code.

Copyright 2026, Taylor Hornby. All rights reserved.

### Dependencies

- [Rust](https://rustup.rs) (stable)
- [Docker](https://docs.docker.com/get-docker/) (for the dev database)

### Development Environment Setup

Clone the workspace (which includes `crackstation-rust`, `crackstation-tester`, and
the `preimage` crate):

```
git clone <repo-url> crackstation-rewrite
cd crackstation-rewrite/crackstation-rust
```

#### Running the Dev Server

```bash
# 1. Start the database (first run creates all databases and tables from dev/01-init.sql)
cd dev
docker compose up -d
cd ..

# 2. Build the test hash indexes (small wordlist, ~50 words)
#    This compiles the preimage CLI and creates indexes in dev/cracking/
dev/setup-test-data.sh

# 3. Copy the dev environment file to the project root
cp dev/dotenv-example .env

# 4. Source the .env file to set necessary environment variables
set -a && source .env && set +a

# 5. Run the unit tests
cargo test

# 6. Run the server
cargo run
```

The dev environment uses Google's
[always-passing test reCAPTCHA key](https://developers.google.com/recaptcha/docs/faq#id-like-to-run-automated-tests-with-recaptcha.-what-should-i-do),
so captcha verification will succeed for any input during development.

The `dev/setup-test-data.sh` script creates a 51-word wordlist and builds indexes
for md5, sha1, sha256, md4, md2, md5(md5), and NTLM. These are tiny (~700 bytes
each) compared to the 190GB production data, but enough to verify cracking works.

Test with:
```
MD5 of 'password':    5f4dcc3b5aa765d61d8327deb882cf99
SHA1 of 'password':   5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
SHA256 of 'password': 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
```

To reset the database to a clean state:

```bash
cd dev
docker compose down -v   # -v removes the data volume
docker compose up -d     # re-creates everything from 01-init.sql
```

#### Running the Integration Tests

While the server and database are running, in another terminal, `cd` into
`crackstation-tester`:

```bash
cd ../crackstation-tester
```

The tester reads its captcha bypass key from a gitignored file. Generate it once
(if it doesn't already exist):

```bash
mkdir -p secrets
xxd -l 32 -p /dev/urandom | tr -d '\n' > secrets/captcha-bypass-key.txt
```

After generating the key, recompute the SHA256 hash and update the
`CAPTCHA_BYPASS_KEY_HASH` constant in `crackstation-rust/src/pages/home.rs`:

```bash
printf '%s' "$(cat secrets/captcha-bypass-key.txt)" | sha256sum
```

Then rebuild the server and run the integration tests:

```bash
CRACKSTATION_URL=http://localhost:3000/ cargo test --no-fail-fast
```

### AI Use Policy

AI tools were used to assist with building this website. All code has been fully
reviewed, and rewritten for clarity when necessary, by myself (a human). If you
would like to submit a PR, using AI is fine, but you must stand by the
correctness of your submission as strongly as you would if you had written the
code yourself.
