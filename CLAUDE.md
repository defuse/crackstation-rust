## Code Quality Standards

### No Silent Failures

Crashes make bugs obvious and fixable. Silent fallbacks make bugs hard to find.
Fail loudly when something goes wrong — do not hide bugs behind default values or
fallback behavior.

- If a condition indicates a programmer error, panic or return a hard error. Do NOT
  silently fall back to a default value.
- Do not wrap values in `Option` or `Result` when they are always expected to be present.
  Use direct access and let it panic if the invariant is violated — that's a bug to fix,
  not a case to handle.
- Do not add defensive code for "impossible" cases. If a match arm, branch, or error
  path should be unreachable, use `unreachable!()`, `panic!()`, or equivalent — not a
  silent default.
- Do not catch or handle errors that indicate bugs. If parsing internal config or
  indexing a data structure you just built can fail, that's a bug — let it panic.
- Prefer `.expect("reason")` over `.unwrap()` so panics are self-documenting.
- Bash scripts must use `set -euo pipefail` to fail on errors, undefined variables, and
  pipe failures.

Bad:
```rust
let port = config.port.unwrap_or(8080); // hides missing config
```

Good:
```rust
let port = config.port.expect("port must be set in config");
```

### Testing

Write unit tests for all new functionality. Tests must rigorously verify intended
behavior — vague assertions are worse than no test because they give false confidence.

- Assert exact expected values with `assert_eq!`, not loose predicates like
  `assert!(result.contains("error"))`.
- Test the actual contract: correct outputs for given inputs, exact error messages,
  specific status codes, boundary conditions.
- Cover edge cases and failure modes, not just the happy path.
- Aim for branch coverage: write tests that exercise every branch, match arm, and
  error path in the code being tested.
- If a function should panic on bad input, test that with
  `#[should_panic(expected = "...")]`.
- Never make a test pass by weakening its assertions. If a test fails, report the
  failure — do not silently fix the code or loosen the test. Test failures are
  information: discuss with the user before changing either the test or the code.
- You may run automated tests yourself. Do NOT start servers, databases, or long-running
  processes — ask the user to do that and tell you when it's ready.

Bad:
```rust
assert!(response.status().is_success());
assert!(body.contains("welcome"));
```

Good:
```rust
assert_eq!(response.status(), StatusCode::OK);
assert_eq!(body, "<h1>Welcome to the dashboard</h1>");
```

### Security

Write code to high-assurance standards. Code involving cryptography, authentication,
parsing untrusted input, crossing FFI boundaries, spawning processes, file system
access, or concurrency requires extra care and scrutiny.

Prefer secure-by-default designs over manual discipline at every call site — e.g.
use a templating engine that escapes all outputs by default rather than escaping at
every output site, or parameterized queries rather than string concatenation for SQL.

For cryptography: do not implement primitives or protocols — use established, audited
libraries. Assume side channels exist: use constant-time operations for all
secret-dependent comparisons, and never expose key material in error messages, logs,
or debug output.

Adding a dependency means trusting its authors with arbitrary code execution. Only use
well-known, actively-maintained crates (e.g. serde, tokio, clap). For anything less
established, ask the user before adding it.

Think adversarially about your own designs and code, trying to break them like an
attacker would.

### Style

- **Naming**: Use clear, descriptive names that read as plain English. Prefer
  `fetch_user_by_email()` over `get_usr()`, `remaining_attempts` over `rem`.
  Abbreviations are acceptable only when universally understood (`id`, `url`, `config`).
- **Functional style**: Prefer iterator chains, `map`, `filter`, `collect` over manual
  loops with mutable accumulators when it makes the intent clearer. Don't force it when
  a loop is more readable.
- **No incomplete code**: Do not leave `todo!()`, stubs, or placeholder implementations.
  Every piece of code should be complete and functional. If a task is too large, discuss
  scope reduction rather than writing skeleton code.

### Commits

Make clear, atomic commits for every logical unit of work. Don't batch unrelated changes.

- Start the message with a verb: Add, Fix, Update, Remove, Refactor
- Be concise but specific: `Add email validation to signup form` not `Update code`
- Commit before moving on to the next task
- After each commit, review the diff for security issues relevant to the code being
  changed — e.g. XSS in HTML templates, SQL injection in queries, command injection
  in process spawning, path traversal in file operations, nonce reuse or timing
  side-channels in cryptography, missing auth checks in API handlers, hardcoded
  secrets anywhere. Report any findings to the user before continuing.

### When In Doubt, Ask

If requirements are ambiguous or a design decision could reasonably go multiple ways,
ask the user rather than guessing. A quick question is cheaper than reworking a wrong
assumption.