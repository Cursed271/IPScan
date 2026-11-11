---
name: Bug report
about: Report a reproducible IPScan issue using authorized test targets and sanitized evidence.
title: "[Bug]: "
labels: bug
assignees: ""
---

<div align="center">

  <img src="https://raw.githubusercontent.com/Cursed271/Cursed271/main/Banner.png" alt="CursedSec banner" width="100%" />

  <h1>IPScan · Bug Report</h1>

  <p align="center">
    <img src="https://img.shields.io/badge/TYPE-BUG_REPORT-C6ECE3?style=for-the-badge&labelColor=262626" alt="Bug report" />
    <img src="https://img.shields.io/badge/PROJECT-IPScan-C6ECE3?style=for-the-badge&labelColor=262626" alt="IPScan" />
  </p>

  <p>Reproducible behavior. Sanitized evidence. Clear technical context.</p>

</div>

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif" alt="" width="100%" />

## Before Submitting

- [ ] I searched existing issues for the same problem.
- [ ] I reviewed the README and known limitations.
- [ ] I tested only within explicitly authorized scope.
- [ ] I used an isolated or controlled test environment where applicable.
- [ ] I removed credentials, API tokens, client information, and sensitive findings.
- [ ] I identified the IPScan version and affected stage or component.
- [ ] I distinguished a tool result from an independently verified security finding.

> Do not attach an unredacted report, customer information, private API response, credential, key, or sensitive infrastructure detail. Follow the repository's security-reporting instructions before disclosing sensitive vulnerabilities.

## Summary

<!-- Describe the problem and its practical effect. -->

## Environment

| Item | Details |
| :--- | :--- |
| IPScan version or commit | |
| Operating system and version | |
| Python version, if applicable | |
| Shell / terminal | |
| Primary dependencies | |
| External tools, if applicable | |
| Network context | Direct / Proxy / VPN / Offline / Other |
| Test environment | Isolated VM / Container / Lab / Other |

## Command or Input

<!-- Include a sanitized command, interactive input, or configuration. Never include credentials or secrets. -->

```text
Paste the sanitized command or input here.
```

## Affected Area

- [ ] Input handling or target selection
- [ ] Core workflow or processing stage
- [ ] External service integration
- [ ] Network or system interaction
- [ ] Output generation
- [ ] Report or artifact export
- [ ] Error handling or exit behavior
- [ ] Documentation
- [ ] Other:

## Steps to Reproduce

1.
2.
3.

## Expected Behavior

<!-- Explain what should happen and how you independently verified it. -->

## Actual Behavior

<!-- Describe errors, missing results, misleading labels, incomplete output, or unexpected behavior. -->

## Sanitized Output

```text
Paste relevant output, traceback, or log excerpt here.
```

## External-Service Context

<!-- Complete only if applicable. Do not include tokens or confidential responses. -->

| Item | Details |
| :--- | :--- |
| Affected provider | |
| HTTP status code | |
| Timeout or rate-limit indication | |
| Approximate observation time and timezone | |
| Reproduced independently | Yes / No / Not tested |

## Diagnostic Checks

- [ ] Used a valid, authorized target or input.
- [ ] Retested with a small controlled test case.
- [ ] Checked required dependencies and tool availability.
- [ ] Checked network, DNS, permissions, and filesystem access where relevant.
- [ ] Checked output-directory permissions.
- [ ] Distinguished an external-service failure from an empty or negative result.
- [ ] Verified the finding independently where possible.

## Screenshots

<!-- Optional. Use sanitized screenshots and remove this section if unnecessary. -->

## Workaround

<!-- Describe a verified workaround, or write "None identified." -->

## Additional Context

<!-- Include relevant provider changes, dependency updates, or environmental observations. -->

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif" alt="" width="100%" />

<div align="center">
  <p>Verify the observation. Preserve the context. Protect the evidence.</p>
  <sub>CursedSec.com · Cursed271 · IPScan</sub>
</div>
