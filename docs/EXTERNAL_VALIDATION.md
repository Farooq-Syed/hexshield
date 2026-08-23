# External Validation Status

## What is verified

HexShield's deterministic, CLI, and model-grounding suites verify tool behavior,
safety boundaries, fallback behavior, and selected adversarial cases. They do not
measure analyst productivity or decision quality in a security operations center.

## Required analyst study

A defensible external evaluation should recruit analysts or suitably trained security
students and compare HexShield-assisted and unassisted triage on the same authorized
evidence bundles. Cases should include authentication abuse, suspicious files, IOC
extraction, host hardening, and incident-response planning.

Primary outcomes should be task accuracy, time to defensible decision, unsupported
claims, missed critical evidence, and confidence calibration. Assignment order should
be randomized, scoring should be blinded to condition, and the study should document
participant experience and model/provider configuration.

## Claim boundary

The current repository supports a systems and safe-tool-design claim. It does not
claim that HexShield improves SOC performance until a controlled analyst study is
completed and, where required, approved through the relevant human-subject process.
