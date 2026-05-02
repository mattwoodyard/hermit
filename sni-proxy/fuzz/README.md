# sni-proxy fuzzers

Coverage-guided fuzzers for the network-facing parsers in
`sni-proxy`. Each target is a `cargo fuzz`-compatible binary in
`fuzz_targets/`.

## What's covered

| Target          | Function fuzzed                          | Trust boundary                                    |
|-----------------|------------------------------------------|---------------------------------------------------|
| `sni`           | `sni::extract_sni`                       | TLS ClientHello bytes from the sandboxed client   |
| `dns_query`     | `dns::parse_query`                       | UDP datagram from the sandboxed client            |
| `dns_answers`   | `dns_forwarder::parse_answers`           | UDP datagram from the upstream resolver           |
| `http_request`  | `http::read_request`                     | HTTP request bytes from the sandboxed client      |
| `http_response` | `http::read_response`                    | HTTP response bytes from the upstream origin      |
| `set_header`    | `http::set_header` (head + name + value) | Credential-script output spliced into a request   |

The MITM, transparent, forward, and DNS listeners all funnel
attacker-controllable bytes into one of these six functions. A
panic, OOB read, or a partial-mutation-on-reject in any of them
is an exploit primitive on the host process.

## Running

`cargo fuzz` requires nightly:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz

cd sni-proxy/fuzz
cargo +nightly fuzz run sni
cargo +nightly fuzz run dns_query
cargo +nightly fuzz run dns_answers
cargo +nightly fuzz run http_request
cargo +nightly fuzz run http_response
cargo +nightly fuzz run set_header
```

Each run produces `corpus/<target>/` (interesting inputs the
fuzzer found) and `artifacts/<target>/` (crash inputs, if any).
Both are git-ignored.

To seed a fuzzer with starter inputs:

```sh
mkdir -p corpus/http_request
cp seed/http_request/* corpus/http_request/
```

A handful of seeds live under `seed/<target>/` — they're tiny
hand-crafted inputs that exercise the smuggling guards and the
common happy paths so libfuzzer doesn't spend the first hour
discovering the byte `G`. Each seed is a short, named file: the
intent is documented by its filename, not its bytes.

## Reproducing a crash

When a fuzzer reports `crash` it writes the exact byte sequence
to `artifacts/<target>/crash-XXXX`. To reproduce:

```sh
cargo +nightly fuzz run http_request artifacts/http_request/crash-XXXX
```

Or run the harness directly with the bytes piped in via the
`fuzz/fuzz_targets/<target>.rs` entry point.

## Adding a new target

1. Add a file under `fuzz_targets/` with the `fuzz_target!` macro.
2. Add a matching `[[bin]]` stanza in `Cargo.toml`.
3. (Optional) drop a few seed inputs under `seed/<target>/`.
4. Document the target in the table above.

Keep targets focused: one parser per binary, no I/O, no sleeps.
The fuzzer wants to iterate millions of times per second.
