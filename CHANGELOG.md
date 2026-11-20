# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.3.0] — 2026-11-20

### Changed

- The command-line interface, diagnosis text, JSON headlines, documentation,
  and screenshots are now in English.

## [0.2.2] — 2026-11-18

### Fixed

- The TUI no longer crashes if the first frame is drawn before the chain exists.
- A background diagnosis error now exits with code `2` instead of looking like success.
- A direct site check tries up to three IP addresses instead of only the first one.
- Progress for parallel site checks is published atomically and no longer jumps backward.

### Added

- Architecture documentation and regression tests for the fixed cases.
- A check that documentation screenshots show the current version.

## [0.2.1] — 2026-11-18

### Changed

- The screen and JSON now share one diagnosis report.
- VPN and site checks are skipped when the direct path to the internet is down.

### Fixed

- The DNS parser rejects malformed replies and no longer loops on compression pointers.

## [0.2.0] — 2026-10-06

### Changed

- The `netdoctor` project was renamed to Eugene.
- The crab Klyeshnya was renamed Eugene.
- The command is now `eugene`, and the distribution is `eugene-crab`.

## [0.1.0] — 2026-10-03

### Added

- The first network doctor: Wi-Fi, router, ISP, VPN, DNS, and site-reachability checks.

[Unreleased]: https://github.com/nikmeee/eugene/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/nikmeee/eugene/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/nikmeee/eugene/compare/7b6502c...v0.2.2
[0.2.1]: https://github.com/nikmeee/eugene/compare/11c120e...7b6502c
[0.2.0]: https://github.com/nikmeee/eugene/compare/7d831c0...11c120e
[0.1.0]: https://github.com/nikmeee/eugene/commit/7d831c0
