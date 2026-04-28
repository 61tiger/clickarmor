# Contributing to ClickArmor

Thanks for taking a look.

This project is intentionally easy to fork and adapt. The most useful contributions will usually fall into one of these buckets:

- improve detection quality
- reduce false positives in real environments
- add regression samples or test coverage
- improve install, debug, or deployment documentation

## Contribution workflow

1. Fork the repository.
2. Create a focused branch.
3. Make the smallest change that solves the problem.
4. Explain the threat model, false-positive tradeoffs, and expected behavior in your pull request.

## Detection change guidance

When changing detections:

- prefer layered signals over single-string matches
- avoid broad rules that will trip on normal Microsoft, Google, Adobe, SharePoint, or OAuth flows
- include notes about what the rule is trying to catch
- call out expected false-positive risk if any

## Sample contributions

If you are sharing phishing samples or bypass cases:

- redact sensitive victim data
- include the delivery pattern or lure context if known
- note whether the sample is ClickFix, brand impersonation, credential harvesting, or AiTM-oriented

## Communication

If your issue is security-sensitive or would make bypass details public, use the path in `SECURITY.md` first.
