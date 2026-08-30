# Changelog

## Unreleased

- Prevented Dependabot from proposing `quick-xml` 0.42+ while the crate keeps
  its Rust 1.85 MSRV and the 0.41 parser API.

## 0.2.2 - 2026-08-29

- Added a runnable recent Security-channel authentication and directory-service
  audit workflow.
- Added scheduled RustSec advisory auditing and weekly dependency monitoring.
- Upgraded `quick-xml` from 0.36 to 0.41 to resolve
  RUSTSEC-2026-0194 and RUSTSEC-2026-0195 denial-of-service advisories.

## 0.2.1 - 2026-08-29

- Corrected stale pre-alpha and dependency documentation after the 0.2 FFI
  migration.
- Declared `win32-min` 0.1.2 as the minimum compatible ABI foundation.
- Declared Rust 1.85 as the MSRV and added CI, DFIR-oriented package metadata,
  and an AI-readable index.

## 0.2.0 - 2026-08-27

- Migrated the Win32 FFI layer from generated Windows bindings to
  `win32-min`.
