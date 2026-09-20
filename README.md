# gradle-verification-audit

Offline linting for Gradle dependency verification metadata.

Gradle’s `gradle/verification-metadata.xml` is a security boundary: it records
the checksums and signatures that builds trust. A generated file can still be
incomplete, contain a typo, duplicate an entry, or quietly rely on a weak hash.
Gradle usually reports those problems only after it starts resolving
dependencies. This small, dependency-free CLI catches the reviewable mistakes
before a build downloads anything.

## Quick start

Run it from a Gradle project checkout:

```console
$ python -m venv .venv
$ .venv/bin/python -m pip install gradle-verification-audit
$ .venv/bin/gradle-verification-audit
PASS gradle-verification-audit — 0 errors, 0 warnings, 0 infos
Scanned 2 component(s), 2 artifact(s), 2 verifier(s).
```

The command is local-only: it reads one XML file, never runs Gradle, never
contacts a repository, and never reads credentials.

Audit a project directory explicitly, use a stricter supply-chain policy, or
produce CI-friendly output:

```console
gradle-verification-audit path/to/project
gradle-verification-audit --secure gradle/verification-metadata.xml
gradle-verification-audit --format sarif > verification.sarif
gradle-verification-audit --format json | jq '.diagnostics'
```

Exit status is `0` for a clean audit and `1` when errors are found. `--strict`
also fails on warnings.

## What it checks

- the Gradle root element and dependency-verification namespace;
- duplicate or incomplete component coordinates (`group:name:version`);
- duplicate or unnamed artifacts;
- checksum length and hexadecimal encoding for MD5, SHA-1, SHA-256, and SHA-512;
- duplicate verifiers and malformed PGP key IDs;
- weak-only verification (`--secure` makes it an error);
- empty verification entries and artifacts with no verifier;
- invalid keyring formats, key-server entries, trusted-key IDs, trust selectors,
  and trust-file regular expressions;
- Gradle-generated checksum origins that deserve independent review.

Every finding has a stable code, source line when available, a useful hint, and
machine-readable JSON/SARIF representations.

## Why this exists

Gradle documents that adding or updating a dependency can fail a build when its
checksum is absent from verification metadata, and recommends manually
reviewing generated metadata. The Gradle issue tracker also contains reports of
metadata differing with local cache state and builds failing later because
entries were missing. Existing tools can generate metadata or verify a running
build, but there is no lightweight, offline preflight for the XML itself.

This project deliberately complements rather than replaces Gradle:

| Tool | Strength | Gap this tool covers |
| --- | --- | --- |
| Gradle dependency verification | Resolves real dependencies and verifies downloaded artifacts | Requires a build/resolution and often network access |
| `./gradlew --write-verification-metadata` | Generates entries | Generated entries still need human review |
| Gradle wrapper checksum | Verifies the Gradle distribution | Does not inspect dependency verification XML |
| **gradle-verification-audit** | Fast, offline XML preflight with CI output | Does not claim to know which dependencies a build will resolve |

## Supported environments

Python 3.10 or newer on macOS, Linux, or Windows. The runtime uses only the
Python standard library. Gradle, a JDK, Docker, and an account are not needed.

## Development

```console
python -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python -m pytest
```

The repository includes clean and intentionally broken XML fixtures. See
[`docs/product-spec.md`](docs/product-spec.md) for scope and non-goals.

## Limitations

This is a static metadata audit. It cannot prove that a checksum matches an
artifact, discover dependencies hidden behind Gradle logic, or decide whether a
trusted key belongs to the expected publisher. Keep running Gradle’s own strict
dependency verification in CI and review generated digests against a trusted
source.

## License

MIT.

