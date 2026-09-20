# Product specification

## Target user

Gradle and Android maintainers who commit `gradle/verification-metadata.xml`
and want a fast, deterministic pull-request check.

## Problem and current workaround

Gradle creates verification metadata while resolving dependencies. Maintainers
usually discover missing entries only when another clean machine or CI job runs
the build, then regenerate the file and manually inspect a large XML diff.

## Why current alternatives are inadequate

- Gradle’s verifier is authoritative but needs a real dependency resolution.
- `--write-verification-metadata` is a generator, not a review-oriented linter.
- wrapper checksum checks protect the Gradle distribution, not dependency
  metadata.
- generic XML linters do not understand Gradle component/artifact/checksum
  semantics or secure hash policy.

## Core use case

Run `gradle-verification-audit` in a checkout or CI. Get actionable diagnostics
for malformed coordinates, duplicate entries, invalid digests, weak-only
verification, malformed trust rules, and unreviewed generated origins.

## Non-goals

- resolving dependencies or contacting Maven repositories;
- downloading artifacts or checking a digest against an artifact;
- evaluating arbitrary Gradle/Groovy/Kotlin build logic;
- replacing Gradle’s runtime verification or a cryptographic key review;
- editing the metadata file automatically.

## Interface

```text
gradle-verification-audit [PATH]
  --format text|json|sarif
  --secure
  --strict
```

`PATH` may be the XML file or a project directory. The default is
`gradle/verification-metadata.xml`.

## Validation strategy

The implementation uses Python’s standard-library XML parser after rejecting
DOCTYPE/ENTITY declarations. Tests cover a clean metadata document, malformed
coordinates, duplicate entries, weak and malformed hashes, invalid trust rules,
missing files, project-directory discovery, JSON/SARIF output, strict mode, and
safe parsing failures.

## Meaningful improvement

The first useful result arrives in milliseconds, without a JDK, Gradle daemon,
network, repository credentials, or dependency cache. The stable diagnostic
codes make it suitable for pre-commit hooks and CI annotations while preserving
Gradle as the final authority.

