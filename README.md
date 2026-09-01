# crackstation-rust

A Rust rewrite of [crackstation.net](https://crackstation.net/), ported from [the original PHP code](https://github.com/defuse/crackstation).

Copyright 2026, Taylor Hornby. All rights reserved.

Code is licensed under [AGPL](/LICENSE). Content is licensed under [CC-BY-SA](https://creativecommons.org/licenses/by-sa/3.0/deed.en).

Hash lookup is provided by the [preimage](https://github.com/defuse/preimage) crate.

### Dependencies

- [Rust](https://rustup.rs) (stable)
- [Docker](https://docs.docker.com/get-docker/) (for the dev database)

### Development Environment Setup

The server itself pulls `preimage` from crates.io, so building and running it needs
nothing but this repo.

Building the dev hash indexes still uses the `preimage` CLI from a sibling checkout,
so clone the two side by side:

```bash
git clone https://github.com/defuse/crackstation-rust
git clone https://github.com/defuse/preimage
cd crackstation-rust
```

`dev/setup-test-data.sh` expects that checkout at `../preimage` relative to this repo.

#### Running the Dev Server

```bash
# 1. Start the database (first run creates all databases and tables from dev/01-init.sql)
cd dev
docker compose up -d
cd ..

# 2. Build the test hash indexes (small wordlist, ~90 words)
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

The `dev/setup-test-data.sh` script creates a 91-word wordlist and builds all 17
indexes the server registers. These are tiny (~1 KB each) compared to the 190GB
production data, but enough to verify cracking works.

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

This software was written with heavy assistance from AI tools, and **has not yet
been reviewed by a human**. I intend to review it and will update this notice once
I have.

If you would like to submit a PR, using AI is fine, but you must stand by the
correctness of your submission as strongly as you would if you had written the
code yourself.
