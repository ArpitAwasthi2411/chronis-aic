# Responsible Disclosure Policy

*Draft for chronis.in/security*

---

## Our Commitment

Chronis takes the security and privacy of our users seriously. The device
handles continuous, deeply personal data, and we treat security research as a
partnership rather than an adversarial relationship. If you have found a
security vulnerability in a Chronis device, our firmware, or our backend
systems, we want to hear from you.

## Scope

**In scope:**
- The Chronis device firmware and its daemons
- The mobile companion application
- The cloud gateway and backend APIs
- The over-the-air update mechanism
- Cryptographic implementation (encryption, key handling, pairing)

**Out of scope:**
- Social engineering of Chronis staff or users
- Physical attacks requiring device theft or destruction
- Denial-of-service attacks against production infrastructure
- Reports from automated scanners without demonstrated impact

## How to Report

Email **security@chronis.in** with:
- A description of the vulnerability and its potential impact
- Step-by-step reproduction instructions
- Any proof-of-concept code or screenshots
- Your name or handle for acknowledgment (optional — anonymous reports are
  welcome)

Please do not disclose the issue publicly until we have had a chance to address
it, per the timeline below.

## Our Response Commitment

| Stage | Timeline |
|-------|----------|
| Acknowledgment of your report | Within **48 hours** |
| Initial assessment and severity rating | Within 5 business days |
| Remediation for confirmed issues | Within **90 days** |
| Public disclosure (coordinated) | After remediation, or 90 days, whichever is sooner |

We commit to keeping you informed throughout the process and to crediting you
in our security acknowledgments unless you prefer to remain anonymous.

## Safe Harbor

We will not pursue legal action against researchers who:
- Make a good-faith effort to avoid privacy violations, data destruction, and
  service interruption
- Only interact with accounts they own or have explicit permission to test
- Report vulnerabilities promptly and do not exploit them beyond what is
  necessary to demonstrate the issue
- Do not publicly disclose before the coordinated timeline

## Recognition

Researchers who report valid, previously-unknown vulnerabilities will be
acknowledged on our security page (with permission). A formal bug-bounty
program with monetary rewards is planned for a future release.

---

*This policy is a living document and will evolve as the product matures.*
