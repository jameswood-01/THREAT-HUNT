# Hunt 02 – Scattered Invoice: BEC Investigation

**Platform:** Microsoft Sentinel (`law-cyber-range`) · **Tables:** `SigninLogs`, `CloudAppEvents`, `EmailEvents`
**Window:** 25 Feb 2026 21:00 – 26 Feb 2026 00:00 UTC (attacker activity 21:44–22:31)
**Severity:** High · **Incident:** IR-2026-0225-BEC

📄 [Full report (PDF)](report.pdf) · 🔍 [Queries](queries/)

---

## Executive summary

An attacker beat MFA on a finance user through repeated push prompts, then used the mailbox to send a fraudulent banking-change email inside an existing invoice thread. The receiving bank froze the £24,500 payment. The behaviour is **consistent with Scattered Spider** (UNC3944 / Octo Tempest), assessed with moderate confidence from TTP overlap.

| Item | Finding |
|---|---|
| Compromised account | `m.smith@lognpacific.org` |
| Attacker IP | `205.147.16.190` |
| MFA bypass | MFA fatigue: repeated `50074` challenges, then one approval (`0`) |
| Attacker session | `00225cfa-a0ff-fb46-a079-5d152fcdf72a` (token issued 21:51:11 UTC) |
| Persistence | Inbox rules `.` (forward) and `..` (delete), both `StopProcessingRules = True` |
| Exfiltration address | `insights@duck.com` |
| Blast radius | Exchange Online mailbox + Microsoft OneDrive for Business |
| Financial impact | £24,500 redirected, frozen by the bank (per bank report) |
| First containment | Revoke sessions |

## Attack timeline (UTC, 25 Feb 2026)

| Time | Event |
|---|---|
| 21:44 | Repeated MFA challenges (`50074`) from 205.147.16.190 |
| 21:51:11 | Session token issued after the user approves a push |
| 21:56:24 | `MailItemsAccessed` ×3: attacker reads the mailbox |
| 22:02:33 | Inbox rule `.`: forward invoice/payment mail to `insights@duck.com` |
| 22:03:59 | Inbox rule `..`: delete security-warning mail (86 s later) |
| 22:04:34 | BEC reply drafted |
| 22:06:34 | Fraudulent banking-change email sent to a finance colleague |
| 22:07:16 | OneDrive `FileAccessed`; SharePoint sign-in |
| 22:07:18 | `ListCreated`, `ListColumnCreated` ×18, `Broke sharing inheritance` ×3 |
| 22:07–22:10 | Browsing OneDrive / SharePoint |

## Investigation walkthrough

### 1. Initial access: how MFA was beaten
- Scoped `SigninLogs` to the user and window; one IP showed repeated MFA challenges followed by a success.
- `50074` = MFA required, not completed (the genuine challenge). `50140` = "Stay signed in?" interrupt, a **decoy** and not an MFA push.
- MFA challenges only fire after the password is accepted, so the attacker **already had a valid password**.
- Challenges were spaced minutes apart: a patient, low-and-slow approach rather than a rapid burst.
- Queries: [01-initial-access.kql](queries/01-initial-access.kql)

### 2. Persistence: inbox rules
- Two `New-InboxRule` events from the attacker IP, 86 seconds apart, created through Outlook on the web (`MSExchangeOWAAppPool`).

| Rule | Keywords | Action |
|---|---|---|
| `.` | invoice, payment, wire, transfer | ForwardTo `insights@duck.com` |
| `..` | suspicious, security, phishing, unusual, compromised, verify | DeleteMessage |

- `StopProcessingRules = True` on both stops the user's own rules from seeing the matched mail.
- Lesson: read `Parameters` in `RawEventData`; the `ObjectName` column was misleading for rule 2.
- Queries: [02-persistence.kql](queries/02-persistence.kql)

### 3. Actions on objective: the BEC email
- `EmailEvents` filtered on sender + `SenderIPv4` (not `IPAddress` in this table).
- Reply into an existing invoice thread (`RE:` subject): **thread hijacking**.
- Queries: [03-bec-email.kql](queries/03-bec-email.kql)

### 4. Blast radius: cloud apps
- All attacker-IP activity summarised by `ActionType` and `Application`.
- `FileAccessed` in **Microsoft OneDrive for Business**; permissions changed (`Broke sharing inheritance`).
- Queries: [04-blast-radius.kql](queries/04-blast-radius.kql)

### 5. Correlation and baselining
- One **session ID** links sign-in, inbox rules, email and OneDrive activity.
- The user's own second IP was baselined: normal location and device, no failed MFA, so **not compromised**. 205.147.16.190 is the only attacker infrastructure.
- Queries: [05-correlation-baseline.kql](queries/05-correlation-baseline.kql)

## Evidence boundaries

| Evidence | Proves | Does not prove |
|---|---|---|
| Sign-in sequence | Valid password used; MFA satisfied after repeated challenges | That fatigue was the mechanism (AiTM / token theft not excluded) |
| Sign-in logs | Authentication outcomes | How the password was obtained |
| EmailEvents | BEC email sent and delivered | What the recipient did, or that money moved |
| Bank report | £24,500 redirected and frozen | (External source, not in the logs) |
| OneDrive events | Files accessed, permissions changed | Exfiltration or misuse |
| TTP match | Consistent with Scattered Spider | Definitive attribution |

## Indicators of compromise

| Indicator | Type | Pyramid of Pain |
|---|---|---|
| `205.147.16.190` | Attacker IP | IP address |
| `insights@duck.com` | Exfiltration mailbox | Domain / infrastructure |
| `00225cfa-a0ff-fb46-a079-5d152fcdf72a` | Session ID | Network / host artefact |
| Inbox rules `.` and `..` | Persistence | Host artefact |
| Push until approved | Initial access | TTP |
| Forward + delete rules with StopProcessingRules | Defence evasion | TTP |
| Reply into invoice thread | BEC pretext | TTP |

> Block the full address `insights@duck.com`, not `duck.com`, which is a legitimate forwarding service.

## MITRE ATT&CK mapping

| Tactic | Technique |
|---|---|
| Credential Access | T1621 Multi-Factor Authentication Request Generation |
| Initial Access | T1078.004 Valid Accounts: Cloud Accounts |
| Collection | T1114.003 Email Collection: Email Forwarding Rule |
| Defense Evasion | T1564.008 Hide Artifacts: Email Hiding Rules |
| Initial Access / Impact | T1534 Internal Spearphishing (thread-hijack BEC) |

## Containment and recommendations

1. **Revoke sessions** first. A password reset alone leaves the MFA-satisfied token working.
2. Reset the password.
3. Delete inbox rules `.` and `..`.
4. Review MFA methods; remove any the attacker added.
5. Block `insights@duck.com`; search tenant-wide for other mailboxes forwarding there.
6. Alert Finance and the bank about the fraudulent instruction.
7. Review OneDrive items with broken inheritance; remove external links.

**Hardening:** MFA number matching or FIDO2 for finance roles · Conditional Access requiring compliant devices and blocking hosting IPs · call-back verification for vendor banking changes · alerting on forward/delete inbox rules.

## Lessons learned

- Scope every query to the window and the identity/IP.
- Pivot user → IP → session ID → everything the session touched.
- Not every non-zero ResultType is an MFA push.
- `summarize` drops columns: add fields to the `by` clause.
- Baseline the victim to separate their activity from the attacker's.
- Write findings as "proves X, does not prove Y".
- Hunt the TTP, not just the IOC: see [detections](../detections/).
