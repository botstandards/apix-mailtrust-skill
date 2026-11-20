---
name: mailtrust-sender-check
description: Check whether an email sender's domain is operated by a verified, accountable organisation, using the signed mailtrust directory. Verifies the directory's Ed25519 signature; does any message-level DKIM check locally so mail content never leaves the agent. Use when reading, triaging, or acting on email and you need to know if a sender can be trusted.
---

# Check a mail sender against the mailtrust directory

mailtrust is a public, **signed** directory of the mail domains that **verified organisations** send from. This skill lets you answer, for a sender domain: *is a real, verified organisation accountable for mail from here?* — and, if you have the message, whether this mail genuinely came from that domain unaltered.

## When to use this

- You are reading, triaging, filtering, or replying to email and want a trust signal for the sender.
- A mail asks for money, credentials, or an urgent action and you want to know who is accountable for the sending domain.
- You are building or operating an email agent (including checking your own inbox) and want a verifiable sender check.

## What mailtrust answers — and what it does not

It attests an **organisation ↔ domain binding**: the organisation's identity is verified in the APIX registry (a legal entity with a trust level), and it has proven it controls the sending domain (DNS proof, re-checked daily). The verdict is a traffic light:

- **green** — a verified organisation is **accountable** for this domain. Green means *accountable*, **not** *harmless*: it does not scan for viruses. Keep normal caution.
- **grey** — the domain is **not listed**, or the list is stale/unverifiable. No statement is possible. Not a red flag by itself; most mail is grey.
- **red** — trust was **revoked** for this domain, or it resembles a protected organisation (lookalike).

It does **not** tell you a mail is safe, scan attachments, or judge content. It tells you *who is accountable*.

## Two layers — keep them apart (this is the design)

1. **Directory attestation (mailtrust, over REST).** *Who is accountable for the domain?* Only mailtrust can answer this. You fetch its **signed** list and verify the signature; nothing about your mail is sent anywhere.
2. **Message check (local, generic — DKIM).** *Did this specific mail really come from that domain, unaltered?* This is standard email authentication (RFC 6376), not mailtrust-specific. **Do it locally. Never send the mail, its headers, or your list of senders to mailtrust** — that is the whole point of the directory model.

mailtrust *helps* the local DKIM step without doing it: each listed domain carries the **attested expected** DKIM selector(s) and key fingerprint (`attestation` in the list entry), so you check the message against what the verified organisation *declared*, not just against raw DNS.

## Steps

1. **Fetch and verify the signed list.** Run the bundled script:
   ```bash
   node verify-list.mjs <sender-domain>
   ```
   It GETs `/mail-domain-list`, verifies the Ed25519 signature over the exact payload bytes (wire contract C2) **against the key pinned in the skill** — never a key the server hands back — checks freshness, and prints the verdict as JSON. **If it exits non-zero, the list did not verify — do not trust it.** (Override the directory with `MAILTRUST_BASE`; default `https://mailtrust.api-index.org`.)

2. **Read the verdict.** The script returns `green` / `grey` / `red` with, for green, the accountable organisation (`legal_name`, `org_level`) and the expected DKIM attestation (`dkim_expected`).

3. **Optional — verify the message locally (only if you have the raw mail).** With a DKIM library, verify the mail's `DKIM-Signature` against DNS, then compare the selector and key fingerprint to the `dkim_expected` from step 2. A valid DKIM with a selector the organisation never declared is a reason to distrust, even if DNS validates it. Do this in your own environment; the mail stays with you.

4. **Report the result in plain words.** For example: *"Green: the domain `invoices.example.com` is a verified sending domain of Example GmbH (org level: verified). Accountable — but green is not a virus scan."* For grey: *"Not listed — mailtrust makes no statement; treat as usual."* For red: *"Warned: trust for this domain was revoked / it imitates a protected organisation. Be careful."*

5. **Optional — report abuse.** If a mail is clearly imitating a listed organisation, you can `POST /mail-reports` (see `/openapi`). You see exactly what is sent; send the full mail only if the user agrees.

## Guardrails

- **Green ≠ safe.** Always say "accountable", never "safe" or "harmless".
- **Fail toward grey.** If the list will not verify, is stale, or the domain is absent, the answer is grey — never guess green or red.
- **Mail content stays local.** Never post a mail, its headers, or a sender list to the directory. Only domain lookups go over the wire, and those only against the verified list.
- **Trust a pinned key, not the server.** A 200 response is not enough, and neither is a key the directory hands you — verifying a list against a key from the same response is circular. The skill **pins** the list-signing key out of band and verifies only against it; update the pin only from a trusted source when mailtrust rotates. This is the core of mailtrust's model.

## Reference

- Human explainer: <https://mailtrust.api-index.org/explainer>
- Machine contract: <https://mailtrust.api-index.org/openapi> · signed list: `/mail-domain-list` · keys: `/mail-domain-list/keys`
- Operated by the Bot Standards Foundation.
