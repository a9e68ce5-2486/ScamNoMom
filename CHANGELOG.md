# Changelog

All notable changes to this project are documented in this file.

## [2026-03-29]

### Changed
- Main branch content was aligned to feature branch `cursor/-bc-48ada0a7-a3e8-4983-bd1e-0b12fed2a88b-2069` (commit `f7e722c`) as requested.
- Pull request #1 status/description was normalized after merge for historical tracking.

### Added
- Production analyze pipeline now supports two-stage live DOM enrichment with:
  - SSRF guardrails (local/private address blocking)
  - timeout and HTML-size limits
  - in-memory TTL cache
- Lightweight supervised scoring channel was added and fused into final scoring.
- Hard-negative learning loop now includes ignore-once / temporary-trust user behaviors in dataset preparation.
- Pipeline automation now includes lightweight model profile generation.

### Notes
- This entry is intended as a release-style record for the branch-to-main overwrite and related high-priority model/generalization improvements.
