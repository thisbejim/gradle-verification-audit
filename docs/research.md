# Opportunity research

The selected job is “catch mistakes in Gradle dependency-verification metadata
before a clean build discovers them.” It is a recurring build and supply-chain
problem for JVM and Android maintainers.

## Evidence

- [Gradle dependency verification documentation](https://docs.gradle.org/current/userguide/dependency_verification.html)
  says a new or updated dependency can fail because its checksum is missing and
  recommends reviewing generated metadata. The same documentation notes that
  generated files are incremental and can retain stale entries.
- [Gradle issue #19228](https://github.com/gradle/gradle/issues/19228) reports
  that verification metadata generated with a warm dependency cache can differ
  from a clean generation, causing CI to fail later on a missing POM checksum.
- [Gradle issue #32623](https://github.com/gradle/gradle/issues/32623) reports
  that not every stored hash is validated during a build, making static review
  of the metadata file useful rather than redundant.
- Large public projects such as [Kotlin’s verification metadata](https://github.com/JetBrains/kotlin/blob/master/gradle/verification-metadata.xml)
  demonstrate that these files become thousands of lines long, making manual
  review error-prone.

## Candidates considered

| Candidate | Decision | Reason |
| --- | --- | --- |
| SBOM diff | Rejected | Several active semantic diff tools already cover CycloneDX/SPDX. |
| npm package publish audit | Rejected | `publint`, `attw`, pack-list tools, and newer tarball scanners overlap heavily. |
| GitHub reusable-workflow contract diff | Rejected | `actionlint` covers local call contracts and new projects already target the same gap. |
| Docker build-context audit | Rejected | BuildKit checks and several new Docker-specific auditors now cover the core failure. |
| Gradle verification metadata audit | Selected | High-integrity file, recurring clean-build failures, no focused offline linter, small durable implementation. |

