# Framework Mapping

Every rule in this pack, tied to a published control. The point is not decoration: a rule
that cites a control can be argued for in an audit, compared against another team's
programme, and defended when somebody asks why it exists. A rule that cites nothing is
only an opinion held firmly.

## What is mapped

- **NIST SSDF**, SP 800-218 version 1.1, by task id (`PW.5.1` and so on). SSDF describes
  practices rather than weaknesses, so a rule maps to the practice that would produce it,
  not to a one-to-one twin.
- **OWASP Top 10 2025**, by category. This is derived rather than chosen: each rule cites a
  CWE, and each 2025 category page publishes the CWE list it covers, so the category
  follows from the weakness. Several results contradict the obvious guess, and those are
  the ones worth reading.
- **CWE**, by id, with the name exactly as MITRE publishes it.
- **OWASP Top 10 for LLM Applications 2025**, for the AI and agent rules.
- **GDPR and CCPA**, for the privacy rules, which map to law rather than to a security
  control set. Those anchors already appear beside the rules themselves; they are
  collected here so one file answers the question.

## What is deliberately not mapped, and why

- **A CWE that no 2025 category covers gets no OWASP row.** Five are in that position and
  each says so on its own line. Assigning them to the nearest-sounding category would make
  the file look complete and be wrong, and a false citation is worse than a missing one.
- **SLSA build levels, OWASP SAMM and ISO 27001 Annex A are not mapped.** SAMM and ISO
  score an organisation's programme, not a code rule, so the mapping would be between
  things of different kinds. SLSA is the closest genuine gap: `SEC-CI-01` and `SEC-DEP-02`
  are steps toward its build track, and nothing here measures a level.
- **No maturity claim is made anywhere in this file.** It says which control a rule serves.
  It does not say the programme reaches any tier of anything.

## How to read an entry

Each rule gives its SSDF tasks, its OWASP Top 10 2025 category, its CWE ids with names,
and for the AI rules its LLM Top 10 entry. A line marked `no 2025 category` means the CWE
appears on none of the ten published lists.

## Security rules

**SEC-SECRET-01**

- SSDF: PW.5.1, PW.7.2, PS.1.1
- OWASP Top 10 2025: A07:2025 Authentication Failures
- CWE: CWE-798 Use of Hard-coded Credentials
- Note: A credential in source is an authentication weakness, not a configuration one.

**SEC-SECRET-02**

- SSDF: PS.1.1, PW.7.2
- OWASP Top 10 2025: A01:2025 Broken Access Control
- CWE: CWE-540 Inclusion of Sensitive Information in Source Code; CWE-538 Insertion of Sensitive Information into Externally-Accessible File or Directory
- Note: The file is in the repository, so the exposure is of the code store itself.

**SEC-SECRET-03**

- SSDF: PW.5.1, PO.5.2
- OWASP Top 10 2025: none. No 2025 category lists this rule's CWE.
- CWE: CWE-214 Invocation of Process Using Visible Sensitive Information (no 2025 category)
- Note: CWE-214 is in no 2025 category list, so no OWASP row is claimed for it.

**SEC-INJ-01**

- SSDF: PW.5.1, PW.7.2
- OWASP Top 10 2025: A05:2025 Injection
- CWE: CWE-89 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**SEC-INJ-02**

- SSDF: PW.5.1, PW.7.2
- OWASP Top 10 2025: A05:2025 Injection
- CWE: CWE-78 Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

**SEC-INJ-03**

- SSDF: PW.5.1, PW.7.2
- OWASP Top 10 2025: A05:2025 Injection; A08:2025 Software or Data Integrity Failures
- CWE: CWE-94 Improper Control of Generation of Code ('Code Injection'); CWE-502 Deserialization of Untrusted Data
- Note: Two weaknesses, and they land in different categories: eval is Injection, deserialization is an integrity failure.

**SEC-WEB-01**

- SSDF: PW.5.1, PW.7.2
- OWASP Top 10 2025: A05:2025 Injection
- CWE: CWE-79 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**SEC-WEB-02**

- SSDF: PW.1.1, PW.5.1, PW.7.2
- OWASP Top 10 2025: A01:2025 Broken Access Control
- CWE: CWE-639 Authorization Bypass Through User-Controlled Key; CWE-862 Missing Authorization
- Note: Object-level authorization, which is the first category in the 2025 edition.

**SEC-WEB-03**

- SSDF: PW.1.1, PW.5.1
- OWASP Top 10 2025: A01:2025 Broken Access Control
- CWE: CWE-918 Server-Side Request Forgery (SSRF)
- Note: SSRF stopped being its own category in 2025 and now sits under access control.

**SEC-WEB-04**

- SSDF: PW.5.1, PW.9.1
- OWASP Top 10 2025: A01:2025 Broken Access Control; A02:2025 Security Misconfiguration
- CWE: CWE-352 Cross-Site Request Forgery (CSRF); CWE-942 Permissive Cross-domain Security Policy with Untrusted Domains; CWE-1004 Sensitive Cookie Without 'HttpOnly' Flag
- Note: Three weaknesses across two categories: CSRF is access control, the CORS and cookie flags are configuration.

**SEC-AUTH-01**

- SSDF: PW.1.3, PW.5.1
- OWASP Top 10 2025: A07:2025 Authentication Failures
- CWE: CWE-306 Missing Authentication for Critical Function
- Note: The finding is a missing check rather than a wrong one, which is why no pattern owns this rule.

**SEC-AUTH-02**

- SSDF: PW.1.3, PW.4.1
- OWASP Top 10 2025: A07:2025 Authentication Failures
- CWE: CWE-287 Improper Authentication
- Note: Using an established implementation is an acquisition practice as much as a coding one, so PW.4.1 sits beside PW.1.3.

**SEC-AUTH-03**

- SSDF: PW.5.1, PW.7.2
- OWASP Top 10 2025: A04:2025 Cryptographic Failures
- CWE: CWE-347 Improper Verification of Cryptographic Signature
- Note: Not the obvious guess: the load-bearing half is the signature check, so the 2025 edition files this under cryptographic failures rather than authentication.

**SEC-AUTH-04**

- SSDF: PW.1.3, PW.9.1
- OWASP Top 10 2025: A07:2025 Authentication Failures
- CWE: CWE-613 Insufficient Session Expiration; CWE-384 Session Fixation
- Note: Two weaknesses in one rule: a session that never expires, and one whose identifier survives a privilege change. Both are authentication failures.

**SEC-AUTH-05**

- SSDF: PW.1.3, PW.9.1
- OWASP Top 10 2025: A07:2025 Authentication Failures
- CWE: CWE-307 Improper Restriction of Excessive Authentication Attempts
- Note: A limit is a configured baseline, hence PW.9.1 rather than a coding practice alone.

**SEC-AUTH-06**

- SSDF: PW.5.1
- OWASP Top 10 2025: none. No 2025 category lists this rule's CWE.
- CWE: CWE-204 Observable Response Discrepancy (no 2025 category)
- Note: CWE-204 is on no 2025 category list, so no OWASP row is claimed for it.

**SEC-CRYPTO-01**

- SSDF: PW.5.1, PW.7.2
- OWASP Top 10 2025: A07:2025 Authentication Failures
- CWE: CWE-295 Improper Certificate Validation
- Note: Disabled certificate validation is filed under authentication, not cryptography.

**SEC-CRYPTO-02**

- SSDF: PW.5.1, PW.7.2
- OWASP Top 10 2025: A04:2025 Cryptographic Failures
- CWE: CWE-327 Use of a Broken or Risky Cryptographic Algorithm; CWE-916 Use of Password Hash With Insufficient Computational Effort

**SEC-CRYPTO-03**

- SSDF: PW.1.1, PW.5.1
- OWASP Top 10 2025: A04:2025 Cryptographic Failures
- CWE: CWE-1240 Use of a Cryptographic Primitive with a Risky Implementation

**SEC-PATH-01**

- SSDF: PW.5.1, PW.7.2
- OWASP Top 10 2025: A01:2025 Broken Access Control
- CWE: CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
- Note: Path traversal is access control in the 2025 edition, not injection.

**SEC-PATH-02**

- SSDF: PW.5.1, PW.9.1
- OWASP Top 10 2025: A01:2025 Broken Access Control
- CWE: CWE-377 Insecure Temporary File

**SEC-LOG-01**

- SSDF: PW.5.1, PW.7.2
- OWASP Top 10 2025: A09:2025 Security Logging and Alerting Failures
- CWE: CWE-532 Insertion of Sensitive Information into Log File

**SEC-ERR-01**

- SSDF: PW.5.1, PW.9.1
- OWASP Top 10 2025: A10:2025 Mishandling of Exceptional Conditions
- CWE: CWE-209 Generation of Error Message Containing Sensitive Information

**SEC-DEP-01**

- SSDF: PW.4.1, PW.4.4, RV.1.1
- OWASP Top 10 2025: A03:2025 Software Supply Chain Failures
- CWE: CWE-1395 Dependency on Vulnerable Third-Party Component

**SEC-DEP-02**

- SSDF: PW.4.1, PW.4.4, PS.3.2
- OWASP Top 10 2025: A03:2025 Software Supply Chain Failures
- CWE: CWE-1357 Reliance on Insufficiently Trustworthy Component

**SEC-DEP-03**

- SSDF: PW.4.1
- OWASP Top 10 2025: A03:2025 Software Supply Chain Failures
- CWE: CWE-1104 Use of Unmaintained Third Party Components
- Note: A question rather than a weakness; the nearest published weakness is an unmaintained component.

**SEC-DEP-04**

- SSDF: RV.1.1, RV.2.1, PW.4.4
- OWASP Top 10 2025: A03:2025 Software Supply Chain Failures
- CWE: CWE-1395 Dependency on Vulnerable Third-Party Component
- Note: A KEV listing is evidence of exploitation now, which is a different claim from a severity score, so it overrides the score rather than adding to it.

## CI and pipeline rules

**SEC-CI-01**

- SSDF: PO.3.2, PW.4.4, PW.6.2
- OWASP Top 10 2025: A03:2025 Software Supply Chain Failures; A08:2025 Software or Data Integrity Failures
- CWE: CWE-1357 Reliance on Insufficiently Trustworthy Component; CWE-494 Download of Code Without Integrity Check
- Note: A moving tag is an untrustworthy component and code fetched without an integrity check, which is why it spans two categories.

**SEC-CI-02**

- SSDF: PO.3.2, PO.5.1, PO.5.2
- OWASP Top 10 2025: A06:2025 Insecure Design
- CWE: CWE-250 Execution with Unnecessary Privileges (no 2025 category); CWE-269 Improper Privilege Management
- Note: CWE-250 is in no 2025 list; the category shown comes from CWE-269.

**SEC-CI-03**

- SSDF: PW.1.1, PO.5.1, PO.3.2
- OWASP Top 10 2025: A08:2025 Software or Data Integrity Failures
- CWE: CWE-829 Inclusion of Functionality from Untrusted Control Sphere

**SEC-CI-04**

- SSDF: PW.5.1, PO.3.2
- OWASP Top 10 2025: A05:2025 Injection
- CWE: CWE-78 Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection'); CWE-94 Improper Control of Generation of Code ('Code Injection')
- Note: An expression pasted into a shell before it runs is command injection with a build system for a target.

## Runtime and detection rules

**SEC-RUN-01**

- SSDF: PW.1.1, RV.1.1
- OWASP Top 10 2025: A09:2025 Security Logging and Alerting Failures
- CWE: CWE-778 Insufficient Logging
- Note: Designing the signal, which is why it sits with threat modelling rather than logging.

**SEC-RUN-02**

- SSDF: PW.8.2, RV.1.1
- OWASP Top 10 2025: A09:2025 Security Logging and Alerting Failures
- CWE: CWE-223 Omission of Security-relevant Information
- Note: Detection is the control whose failure mode is silence, so it needs a firing test.

**SEC-RUN-03**

- SSDF: PS.3.1
- OWASP Top 10 2025: A09:2025 Security Logging and Alerting Failures
- CWE: CWE-778 Insufficient Logging
- Note: Retention: evidence that has rotated away cannot be produced when it is wanted.

## Privacy rules

**PRIV-LOG-01**

- SSDF: PW.1.1, PW.5.1
- OWASP Top 10 2025: A01:2025 Broken Access Control; A09:2025 Security Logging and Alerting Failures
- CWE: CWE-532 Insertion of Sensitive Information into Log File; CWE-359 Exposure of Private Personal Information to an Unauthorized Actor
- Note: GDPR Art. 5(1)(f). CCPA reasonable security.

**PRIV-LOG-02**

- SSDF: PW.5.1
- OWASP Top 10 2025: A01:2025 Broken Access Control; A10:2025 Mishandling of Exceptional Conditions
- CWE: CWE-209 Generation of Error Message Containing Sensitive Information; CWE-359 Exposure of Private Personal Information to an Unauthorized Actor
- Note: GDPR Art. 5(1)(f).

**PRIV-MIN-01**

- SSDF: PO.1.2, PW.1.1
- OWASP Top 10 2025: not applicable. This rule cites no CWE to derive one from.
- CWE: none. This rule is a legal or process obligation, not a code weakness.
- Note: GDPR Art. 5(1)(c) data minimisation.

**PRIV-MIN-02**

- SSDF: PO.1.2, PW.1.1
- OWASP Top 10 2025: not applicable. This rule cites no CWE to derive one from.
- CWE: none. This rule is a legal or process obligation, not a code weakness.
- Note: GDPR Art. 5(1)(b) purpose limitation. CCPA notice at collection.

**PRIV-RET-01**

- SSDF: PO.1.2
- OWASP Top 10 2025: not applicable. This rule cites no CWE to derive one from.
- CWE: none. This rule is a legal or process obligation, not a code weakness.
- Note: GDPR Art. 5(1)(e) storage limitation.

**PRIV-RET-02**

- SSDF: PO.1.2, PW.1.2
- OWASP Top 10 2025: not applicable. This rule cites no CWE to derive one from.
- CWE: none. This rule is a legal or process obligation, not a code weakness.
- Note: GDPR Art. 17 erasure. CCPA right to delete.

**PRIV-RET-03**

- SSDF: PO.1.2, PW.1.2
- OWASP Top 10 2025: not applicable. This rule cites no CWE to derive one from.
- CWE: none. This rule is a legal or process obligation, not a code weakness.
- Note: GDPR Art. 17, applied to replicas and backups.

**PRIV-ACC-01**

- SSDF: PW.5.1, PW.9.1
- OWASP Top 10 2025: A06:2025 Insecure Design
- CWE: CWE-311 Missing Encryption of Sensitive Data; CWE-312 Cleartext Storage of Sensitive Information
- Note: GDPR Art. 32 security of processing.

**PRIV-ACC-02**

- SSDF: PW.9.1, PW.9.2
- OWASP Top 10 2025: A01:2025 Broken Access Control
- CWE: CWE-285 Improper Authorization; CWE-552 Files or Directories Accessible to External Parties
- Note: GDPR Art. 9 special categories, Art. 32.

**PRIV-XFER-01**

- SSDF: PO.1.3, PW.1.1
- OWASP Top 10 2025: A04:2025 Cryptographic Failures
- CWE: CWE-319 Cleartext Transmission of Sensitive Information
- Note: GDPR Art. 28 processors.

**PRIV-XFER-02**

- SSDF: PO.1.3, PW.1.1
- OWASP Top 10 2025: not applicable. This rule cites no CWE to derive one from.
- CWE: none. This rule is a legal or process obligation, not a code weakness.
- Note: GDPR Chapter V, international transfers.

**PRIV-CONSENT-01**

- SSDF: PO.1.2
- OWASP Top 10 2025: not applicable. This rule cites no CWE to derive one from.
- CWE: none. This rule is a legal or process obligation, not a code weakness.
- Note: GDPR Art. 6 lawful basis, Art. 7 consent.

**PRIV-CONSENT-02**

- SSDF: PO.1.2
- OWASP Top 10 2025: not applicable. This rule cites no CWE to derive one from.
- CWE: none. This rule is a legal or process obligation, not a code weakness.
- Note: GDPR Art. 7. CCPA notice at collection.

**PRIV-RIGHTS-01**

- SSDF: PO.1.2, PW.1.2
- OWASP Top 10 2025: not applicable. This rule cites no CWE to derive one from.
- CWE: none. This rule is a legal or process obligation, not a code weakness.
- Note: GDPR Art. 15 access, Art. 20 portability. CCPA opt-out.

**PRIV-ANON-01**

- SSDF: PW.5.1, PW.8.2
- OWASP Top 10 2025: A01:2025 Broken Access Control
- CWE: CWE-359 Exposure of Private Personal Information to an Unauthorized Actor
- Note: GDPR Art. 5(1)(f), applied to test data.

**PRIV-ANON-02**

- SSDF: PW.5.1
- OWASP Top 10 2025: not applicable. This rule cites no CWE to derive one from.
- CWE: none. This rule is a legal or process obligation, not a code weakness.
- Note: GDPR Recital 26, on what counts as anonymous.

## AI and agent rules

**SEC-AI-INJ-01**

- SSDF: PW.1.1, PW.5.1
- OWASP Top 10 2025: none. No 2025 category lists this rule's CWE.
- CWE: CWE-1427 Improper Neutralization of Input Used for LLM Prompting (no 2025 category)
- LLM Top 10 2025: LLM01:2025 Prompt Injection
- Note: CWE-1427 is not in any 2025 category list, which is expected: the AI weaknesses are newer than the edition.

**SEC-AI-INJ-02**

- SSDF: PW.1.1, PW.5.1
- OWASP Top 10 2025: none. No 2025 category lists this rule's CWE.
- CWE: CWE-1427 Improper Neutralization of Input Used for LLM Prompting (no 2025 category)
- LLM Top 10 2025: LLM01:2025 Prompt Injection; LLM06:2025 Excessive Agency

**SEC-AI-INJ-03**

- SSDF: PW.1.1, PW.5.1
- OWASP Top 10 2025: none. No 2025 category lists this rule's CWE.
- CWE: CWE-1427 Improper Neutralization of Input Used for LLM Prompting (no 2025 category)
- LLM Top 10 2025: LLM01:2025 Prompt Injection

**SEC-AI-INJ-04**

- SSDF: PW.5.1, PW.7.2
- OWASP Top 10 2025: none. No 2025 category lists this rule's CWE.
- CWE: CWE-1426 Improper Validation of Generative AI Output (no 2025 category)
- LLM Top 10 2025: LLM05:2025 Improper Output Handling

**SEC-AI-INJ-05**

- SSDF: PW.1.2
- OWASP Top 10 2025: none. No 2025 category lists this rule's CWE.
- CWE: CWE-1426 Improper Validation of Generative AI Output (no 2025 category)
- LLM Top 10 2025: LLM09:2025 Misinformation

**SEC-AI-RAG-01**

- SSDF: PW.1.1, PW.5.1
- OWASP Top 10 2025: A01:2025 Broken Access Control
- CWE: CWE-862 Missing Authorization; CWE-285 Improper Authorization
- LLM Top 10 2025: LLM02:2025 Sensitive Information Disclosure

**SEC-AI-RAG-02**

- SSDF: PW.1.1, PW.5.1
- OWASP Top 10 2025: A01:2025 Broken Access Control
- CWE: CWE-639 Authorization Bypass Through User-Controlled Key
- LLM Top 10 2025: LLM02:2025 Sensitive Information Disclosure; LLM08:2025 Vector and Embedding Weaknesses

**SEC-AI-RAG-03**

- SSDF: PW.1.1, PW.5.1
- OWASP Top 10 2025: none. No 2025 category lists this rule's CWE.
- CWE: CWE-1427 Improper Neutralization of Input Used for LLM Prompting (no 2025 category)
- LLM Top 10 2025: LLM01:2025 Prompt Injection; LLM04:2025 Data and Model Poisoning

**SEC-AI-RAG-04**

- SSDF: PW.1.2, PW.8.2
- OWASP Top 10 2025: A01:2025 Broken Access Control
- CWE: CWE-359 Exposure of Private Personal Information to an Unauthorized Actor
- LLM Top 10 2025: LLM02:2025 Sensitive Information Disclosure; LLM08:2025 Vector and Embedding Weaknesses
- Note: Also GDPR Art. 17: an index entry that survives deletion is undeleted personal data.

**SEC-AI-RAG-05**

- SSDF: PS.3.2, PW.1.2
- OWASP Top 10 2025: not applicable. This rule cites no CWE to derive one from.
- CWE: none. This rule is a legal or process obligation, not a code weakness.
- LLM Top 10 2025: LLM08:2025 Vector and Embedding Weaknesses

**SEC-AI-MCP-01**

- SSDF: PW.4.1, PW.4.4, PO.3.2
- OWASP Top 10 2025: A03:2025 Software Supply Chain Failures; A08:2025 Software or Data Integrity Failures
- CWE: CWE-1357 Reliance on Insufficiently Trustworthy Component; CWE-829 Inclusion of Functionality from Untrusted Control Sphere
- LLM Top 10 2025: LLM03:2025 Supply Chain

**SEC-AI-MCP-02**

- SSDF: PW.1.1, PW.5.1
- OWASP Top 10 2025: none. No 2025 category lists this rule's CWE.
- CWE: CWE-1427 Improper Neutralization of Input Used for LLM Prompting (no 2025 category)
- LLM Top 10 2025: LLM01:2025 Prompt Injection

**SEC-AI-MCP-03**

- SSDF: PO.1.3, PW.1.1
- OWASP Top 10 2025: A01:2025 Broken Access Control
- CWE: CWE-200 Exposure of Sensitive Information to an Unauthorized Actor
- LLM Top 10 2025: LLM02:2025 Sensitive Information Disclosure

**SEC-AI-MCP-04**

- SSDF: PW.1.1, PO.5.1
- OWASP Top 10 2025: A06:2025 Insecure Design
- CWE: CWE-269 Improper Privilege Management
- LLM Top 10 2025: LLM06:2025 Excessive Agency

## Sources, each read on 2026-09-02

- NIST SSDF SP 800-218 version 1.1, and its published task table:
  https://csrc.nist.gov/pubs/sp/800/218/final
- OWASP Top 10 2025, the ten category pages under https://owasp.org/Top10/2025/ , each of
  which publishes the CWE list this file's category column is derived from.
- OWASP Top 10 for LLM Applications 2025: https://genai.owasp.org/llm-top-10/
- CWE, the comprehensive catalogue: https://cwe.mitre.org/data/csv/2000.csv.zip

SP 800-218 Revision 1 (SSDF 1.2) is a draft at the time of writing, so the task ids above
are version 1.1. Note that version 1.1 has no PW.3, and no PW.4.3; a mapping that cites
either is citing a task that does not exist.
