#!/usr/bin/env bash
set -euo pipefail

# Creates small test indexes for local crackstation development.
# These are tiny (~100 words) so the hash cracking feature works locally
# without the 190GB production data.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CRACKING_DIR="$SCRIPT_DIR/cracking"
# A function, not a string: an unquoted "$PREIMAGE" relied on word splitting to become
# separate arguments, which meant any space anywhere in the path -- a checkout under
# "My Documents", a CI workspace with a space -- split the manifest path into two broken
# arguments and failed the build with a confusing error. "$@" keeps the caller's
# arguments intact and the quoted path survives spaces.
preimage() {
    cargo run --manifest-path="$PROJECT_DIR/../preimage/preimage/Cargo.toml" -- "$@"
}

echo "=== Setting up test cracking data ==="
echo "Output directory: $CRACKING_DIR"
mkdir -p "$CRACKING_DIR"

# Create a small test wordlist with common passwords
WORDLIST="$CRACKING_DIR/REALUNIQ.lst"
echo "Creating test wordlist at $WORDLIST..."
# NOTE: the list ends with a deliberate empty line. Production's REALUNIQ.lst
# contains one too — sha256("") cracks on the live site — so the empty word is
# real dictionary data, and hashes of the empty string must keep resolving to it.
#
# The list also carries deliberately hostile entries, added below. Production's
# wordlist is assembled from public breach dumps, so it genuinely contains markup,
# whitespace-only passwords and bytes that are not valid UTF-8 — but every word here
# used to be a tame lowercase ASCII string, so nothing a developer ran locally ever
# exercised the HTML-escaping path, the whitespace-preservation path or the lossy
# UTF-8 display path. A regression in any of them looked perfect in dev.
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
<script>alert(1)</script>
<b>bold</b>
a&b
"quoted"
it's
 leading
trailing 
two  spaces
	tabbed
   
WORDS

# A word that is not valid UTF-8, which a quoted heredoc cannot carry. Production's
# wordlist has these -- they are why NTLM's encoder returns None and the builder skips
# a word, and why the results table has a lossy-UTF-8 display path at all.
printf 'inv\xff\xfeword\n' >> "$WORDLIST"

# A collision block larger than the results table will show. LM uppercases and hashes
# the first seven characters into the index prefix, so every "password*" word lands in
# one block: a query for LM("password") returns one exact match and every other entry
# as a near miss. Production's tables are full of blocks like this -- shared prefixes
# are what a password dictionary *is* -- but the dev list had four such words, well
# under the display cap, so the truncation path and its "N more not shown" row never
# ran locally. Thirty entries puts it ten over the cap.
for SUFFIX in $(seq 3 28); do
    echo "password$SUFFIX" >> "$WORDLIST"
done

# Restore the deliberate empty final word. It must stay last: production's REALUNIQ.lst
# ends with one, and sha256("") cracks on the live site.
printf '\n' >> "$WORDLIST"

# Create the "huge" wordlist. In production HUGELIST.lst is a larger dictionary
# than REALUNIQ.lst; the md5-huge and sha1-huge tables use it as a fallback.
# For dev, it's a small list with some words unique to it (e.g. "elephant") and
# some shared with REALUNIQ (e.g. "hello") to test deduplication via early_exit.
# "monkey" is intentionally absent so tests can verify small-only lookups.
HUGELIST="$CRACKING_DIR/HUGELIST.lst"
echo "Creating huge wordlist at $HUGELIST..."
cat > "$HUGELIST" << 'WORDS'
hello
Hello
HELLO
elephant
giraffe
telescope
password
winter
umbrella
volcano
crystal
phantom
WORDS

# Build and sort indexes for all 15 algorithms using REALUNIQ.lst.
# Algorithm names must match `preimage list` output exactly.
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
    preimage create --algorithm "$ALG" --wordlist "$WORDLIST" --output "$IDX"
    echo "Sorting $ALG index..."
    preimage sort --ram "$IDX"
    echo "Verifying $ALG index..."
    preimage check "$IDX"
done

# Build md5-huge and sha1-huge indexes from HUGELIST.lst.
# These are the fallback tables that use the larger dictionary.
for ALG_HUGE in "md5:md5-huge.idx" "sha1:sha1-huge.idx"; do
    ALG="${ALG_HUGE%%:*}"
    IDX_NAME="${ALG_HUGE##*:}"
    IDX="$CRACKING_DIR/$IDX_NAME"
    echo "Building $IDX_NAME index (huge, from HUGELIST)..."
    preimage create --algorithm "$ALG" --wordlist "$HUGELIST" --output "$IDX"
    echo "Sorting $IDX_NAME index..."
    preimage sort --ram "$IDX"
    echo "Verifying $IDX_NAME index..."
    preimage check "$IDX"
done

echo ""
echo "=== Test cracking data ready ==="
echo "Set CRACKING_DIR=$CRACKING_DIR when running the server."
echo ""
echo "Test with:"
echo "  MD5 of 'password':  5f4dcc3b5aa765d61d8327deb882cf99"
echo "  SHA1 of 'password': 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
echo "  SHA256 of 'password': 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
echo "  MD5 of 'elephant' (HUGELIST-only): e4b48fd541b3dcb99cababc87c2ee88f"
