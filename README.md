# ClickArmor

The tool built to stop ClickFix, one of today's fastest-growing phishing tactics, is now open source.

ClickArmor is a browser-native phishing and social-engineering defense extension built to detect:

- ClickFix command-execution lures
- brand impersonation and credential harvesting
- clipboard hijacking and malicious payload staging
- multi-stage loader behavior and page replacement tricks
- AiTM-style phishing flows, including device-code phishing

Everything runs locally in the browser. The goal is simple: catch real attack behavior at the point of execution without relying on cloud browsing analysis.

## What is in this repo

This repository contains the Chromium extension source currently used for ClickArmor's local detection engine:

- `background.js`: service worker and extension state
- `clipboard-hook-early.js`: early clipboard interception logic
- `content.js`: page-side warning and block experience
- `page-analyzer.js`: page-level phishing and AiTM analysis
- `form-detector.js`: credential-harvesting and sensitive-form analysis
- `detector.js`: clipboard payload scoring
- `rules.json`: built-in ClickFix and lure signatures
- `whitelist.json`: built-in remote allowlist stub

## Current coverage

ClickArmor is structured around layered browser-side detection rather than a single URL or keyword check.

It currently looks for:

- fake CAPTCHA and human-verification lures
- fake browser updates and staged payload instructions
- PowerShell / terminal copy-paste chains
- clipboard abuse via `writeText`, `execCommand`, and related APIs
- hidden or obfuscated command payloads
- brand impersonation on unofficial domains
- credential-harvesting pages and sensitive-form lures
- encrypted phishing loaders and serverless impersonation hosts
- high-confidence AiTM flows such as device-code phishing relays

## Install locally

1. Clone or download this repository.
2. Open `chrome://extensions` in Chrome or another Chromium-based browser.
3. Enable **Developer mode**.
4. Click **Load unpacked**.
5. Select this repository folder.

## Philosophy

ClickArmor reached beta users across the US, UK, and Germany, and a lot of the product improved through a continuous feedback loop from friends, testers, and people in the security community.

I am open sourcing it because the broader security community can tune false positives, adapt detections to different environments, and push the project further than I could alone without visibility into every deployment.

If you want to fork it, tune it, and make it your own, please do.

## Contributing

Contributions are welcome, especially around:

- false-positive reduction
- new phishing and AiTM detections
- test harnesses and sample validation
- browser compatibility improvements
- documentation and deployment guidance

See `CONTRIBUTING.md` for the short workflow.

## Security

If you have a bypass, active false negative, or sensitive detection issue, please use the guidance in `SECURITY.md` rather than posting full exploit details in a public issue.

## License

This repository is released under the MIT License. See `LICENSE`.
