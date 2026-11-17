# Proposed distribution notices — unapproved staging templates

**DRAFT ONLY — NOT A COMPLIANCE-READY PACKAGE — PUBLIC DISTRIBUTION BLOCKED.**

These templates capture the texts and decisions that must be reviewed by the owner/legal reviewer. They are intentionally stored outside the existing Linux and Windows package assembly input lists. Neither packaging/build-deb.sh nor packaging/windows/build-windows.sh installs them as authoritative licence notices.

Required approved outputs after legal review:

- Linux: /usr/share/doc/holochain-music/copyright (completed and legally reviewed DEP-5-style or equivalent notices), licences/NOTICE and source-access instructions as required. Ship machine-readable SBOMs and source archive hashes next to the .deb and audit their discoverability inside/outside the package as approved.
- Windows: licenses/THIRD-PARTY.txt, all upstream licence texts including CAL-1.0, full Python and wheel notices, PortAudio and Inter-OFL, Rust transitive attribution/NOTICE, exact source locations and source archives/SBOMs. Existing unsigned private-test warnings must remain until owner approves a distribution plan.

Do not copy incomplete templates into an installer in order to claim B5/L04 is fixed; incomplete licence or source details must fail packaging acceptance. See docs/release-dependency-inventory.md and docs/release-licensing-decision-record.md.
