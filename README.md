# apix-mailtrust-skill

An [Agent Skill](https://skills.sh) that lets an AI agent check whether an email sender's domain is
operated by a **verified, accountable organisation**, using the signed
[mailtrust](https://mailtrust.api-index.org/explainer) directory.

Use it when your agent reads, triages, or acts on email — including your own inbox — and needs a
trustworthy signal about who is behind a sender.

## Install

```bash
npx skills add botstandards/apix-mailtrust-skill
```

The skill lives in [`skills/mailtrust-sender-check/`](skills/mailtrust-sender-check/SKILL.md). It works
with Claude Code, Cursor, Codex, Copilot and other agents that consume Agent Skills.

## What it does

Given a sender domain (and, if you have it, the raw message), the skill returns a traffic-light verdict:

- **green** — a verified organisation is **accountable** for the domain (identity verified in the APIX
  registry, control of the domain proven). Green means *accountable*, not *harmless*.
- **grey** — not listed, or the list is stale/unverifiable. No statement possible.
- **red** — trust was revoked, or the domain imitates a protected organisation (lookalike).

Two layers, kept apart:

1. **Directory attestation** (over the mailtrust REST API) — *who is accountable for the domain?* The
   agent fetches the **signed** list and verifies it; nothing about your mail is sent anywhere.
2. **Message check** (local, generic DKIM) — *did this mail really come from there, unaltered?* Standard
   email authentication, done locally. **Mail content never leaves the agent.**

## Trust model

The skill **pins** the directory's Ed25519 list-signing key and verifies the signed list only against the
pinned key — never against a key the server hands back. This is the core of mailtrust's design: clients
pin the key out of band, so a hostile or intercepted response cannot substitute its own. On key rotation,
a new skill release adds the announced next key and drops the retired one.

## Links

- Human explainer: <https://mailtrust.api-index.org/explainer>
- Machine contract (OpenAPI): <https://mailtrust.api-index.org/openapi>
- Operated by the [Bot Standards Foundation](https://botstandards.org).

## License

[MIT](LICENSE) © Bot Standards Foundation.
