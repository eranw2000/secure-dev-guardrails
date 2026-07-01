---
name: threat-model
description: Produce a design-time threat model for a feature or system, using STRIDE for security threats and LINDDUN for privacy threats, anchored to the org standards. Writes THREAT-MODEL.md with identified threats, their severity, and mitigations that become NFR-SEC-* / NFR-PRIV-* requirements. Use during design (feeds the architect skill) or when the user says "threat model", "STRIDE", "LINDDUN", "what could go wrong with this design", "attack surface". Design-time and proactive, unlike security-review and privacy-review which inspect existing code.
---

# Threat Model (STRIDE + LINDDUN)

You map what could go wrong in a design before it is built, so the mitigations become explicit
requirements the architect and reviewers can trace. STRIDE covers security threats; LINDDUN
covers privacy threats. Run both because your organization holds personal data.

## Inputs

1. The design under review: a SPEC.md, REQUIREMENTS.md, a design doc, or a description in the
   conversation. If only a verbal description exists, restate the system in two or three
   sentences and confirm before modeling.
2. `standards/security-standards.md` and `standards/privacy-standards.md` for the rule
   vocabulary the mitigations should map to.
3. `standards/severity-taxonomy.md` for banding.

## Process

### 1. Sketch the system and its trust boundaries
List the components, the data stores, the external actors, and the data flows between them.
Mark every point where data crosses a trust boundary (user to server, service to service,
service to third party, app to data store). Threats cluster on boundaries. If the design tool
in use is draw.io (org default), reference or produce a data-flow diagram; otherwise a labeled
list of flows is enough.

### 2. Identify the assets
What is worth attacking or worth protecting: credentials, personal data, money movement,
integrity of records, availability of the service. Tie each asset to the data flows that touch
it.

### 3. STRIDE pass (security threats)
For each component and data flow, walk the six categories and record concrete threats:
- **Spoofing:** can an actor impersonate a user or service? (authn)
- **Tampering:** can data in transit or at rest be modified? (integrity, SEC-INJ, SEC-CRYPTO)
- **Repudiation:** can an actor deny an action with no audit trail? (logging, SEC-LOG)
- **Information disclosure:** can data leak? (SEC-WEB-02 authz, SEC-CRYPTO transport, PRIV-ACC)
- **Denial of service:** can the component be exhausted or wedged?
- **Elevation of privilege:** can an actor gain rights they should not have? (authz, IDOR)

### 4. LINDDUN pass (privacy threats)
For each flow that touches personal data, walk the seven categories:
- **Linkability:** can two records be linked to the same person who should stay separate?
- **Identifiability:** can a pseudonymous record be tied back to a real person?
- **Non-repudiation (privacy):** is a person unable to deny an action they should be able to?
- **Detectability:** can an observer tell that a record about a person exists?
- **Disclosure of information:** is personal data exposed beyond its purpose? (PRIV-ACC, PRIV-XFER)
- **Unawareness:** does the person lack notice/consent or control? (PRIV-CONSENT, PRIV-RIGHTS)
- **Non-compliance:** does the design violate retention/minimization/transfer rules?
  (PRIV-MIN, PRIV-RET, PRIV-XFER)

### 5. Rate and mitigate
For each threat: band it (Blocker/Major/Nit per the taxonomy, by likelihood and impact), then
state a mitigation. Each mitigation that must hold becomes a requirement: phrase it as an
`NFR-SEC-*` or `NFR-PRIV-*` line the architect can drop into REQUIREMENTS/SPEC and the reviewers
can later trace.

### 6. Write THREAT-MODEL.md

```markdown
# THREAT MODEL, <feature/system>

**Modeled at:** <YYYY-MM-DD>
**Scope:** <what is in / out of scope>

## System sketch
Components, data stores, external actors, trust boundaries (or a link to the data-flow diagram).

## Assets
- <asset>, touched by <flows>

## Security threats (STRIDE)
### T-S-1: <title>  [Blocker|Major|Nit]
- **Category:** Spoofing | Tampering | ...
- **Where:** <component / flow / boundary>
- **Threat:** what an attacker does.
- **Mitigation:** the control. -> proposes NFR-SEC-<n>: <requirement text>

## Privacy threats (LINDDUN)
### T-P-1: <title>  [Blocker|Major|Nit]
- **Category:** Linkability | Identifiability | ...
- **Where:** <flow>
- **Threat:** the privacy harm.
- **Mitigation:** the control. -> proposes NFR-PRIV-<n>: <requirement text>

## Proposed requirements (hand-off to architect)
- NFR-SEC-<n>: ...
- NFR-PRIV-<n>: ...

## Residual risks
Threats accepted without full mitigation, with the reason and owner.
```

## Guardrails

- Model the design as described; do not invent components that are not there. If the design is
  too vague to model a boundary, say so and ask.
- Every Blocker/Major threat needs a named mitigation or an explicit residual-risk acceptance.
- The output is requirements, not code. Hand the NFR lines to the architect skill.
- Do not claim the model is exhaustive. Note the areas you did not have enough detail to cover.
