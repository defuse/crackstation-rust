#!/usr/bin/env bash
set -euo pipefail

# Creates small test indexes for local crackstation development.
# These are tiny (~100 words) so the hash cracking feature works locally
# without the 190GB production data.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
WORKSPACE_DIR="$(dirname "$PROJECT_DIR")"
CRACKING_DIR="$SCRIPT_DIR/cracking"
PREIMAGE="cargo run --manifest-path=$WORKSPACE_DIR/Cargo.toml -p preimage --"

echo "=== Setting up test cracking data ==="
echo "Output directory: $CRACKING_DIR"
mkdir -p "$CRACKING_DIR"

# Create a small test wordlist with common passwords
WORDLIST="$CRACKING_DIR/REALUNIQ.lst"
echo "Creating test wordlist at $WORDLIST..."
cat > "$WORDLIST" << 'WORDS'
password
123456
12345678
qwerty
abc123
monkey
1234567
letmein
trustno1
dragon
baseball
iloveyou
master
sunshine
ashley
michael
shadow
123123
654321
superman
qazwsx
hello
Hello
HELLO
charlie
donald
password1
password123
welcome
football
jesus
ninja
mustang
password2
princess
admin
login
starwars
121212
abc
cheese
access
test
computer
flower
whatever
internet
samsung
pepper
cookie
killer
joshua
matrix
WORDS

# Build and sort indexes for the algorithms we want to test.
# Only building md5, sha1, and sha256 since the wordlist is small.
# Algorithm name -> index file name mapping
# Algorithm names must match `preimage algorithms` output exactly.
# Index file names must match what cracking.rs registers.
declare -A ALGO_MAP=(
    ["md5"]="md5.idx"
    ["sha1"]="sha1.idx"
    ["sha256"]="sha256.idx"
    ["NTLM"]="ntlm.idx"
    ["md5(md5)"]="md5md5.idx"
    ["md4"]="md4.idx"
    ["md2"]="md2.idx"
    ["LM"]="lm.idx"
    ["MySQL4.1+"]="mysql4.1+.idx"
    ["sha224"]="sha224.idx"
    ["sha384"]="sha384.idx"
    ["sha512"]="sha512.idx"
    ["whirlpool"]="whirlpool.idx"
    ["ripemd160"]="ripemd160.idx"
    ["QubesV3.1BackupDefaults"]="qubesv3.1.idx"
)

for ALG in "${!ALGO_MAP[@]}"; do
    IDX="$CRACKING_DIR/${ALGO_MAP[$ALG]}"
    echo "Building $ALG index..."
    $PREIMAGE create "$ALG" "$WORDLIST" "$IDX"
    echo "Sorting $ALG index..."
    $PREIMAGE sort --ram "$IDX"
    echo "Verifying $ALG index..."
    $PREIMAGE check "$IDX"
done

echo ""
echo "=== Test cracking data ready ==="
echo "Set CRACKING_DIR=$CRACKING_DIR when running the server."
echo ""
echo "Test with:"
echo "  MD5 of 'password':  5f4dcc3b5aa765d61d8327deb882cf99"
echo "  SHA1 of 'password': 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
echo "  SHA256 of 'password': 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
