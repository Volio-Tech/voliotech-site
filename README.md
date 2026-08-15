# Volio Tech

Static brand site for Volio Tech, plus a private, encrypted team dossier used
during client proposals.

- `index.html` — public landing page
- `team.html` — private team dossier (unlocked by an access key)
- `team.enc.json` — the roster, encrypted (safe to commit)
- `tools/encrypt.mjs` — turns your private roster into `team.enc.json`

No build step, no framework, no backend. Deploys from the repo root.

---

## ⚠️ This is a public repository

Anything committed here is world-readable **permanently** — deleting a file does
not remove it from git history, and GitHub Pages has no way to password-protect
a page. Employee data therefore never gets committed in plaintext.

`.gitignore` blocks the two files that must stay local:

| File | Status |
|---|---|
| `team.private.json` | **Never committed** — real names, contacts, CV detail |
| `photos/` | **Never committed** — inlined into the encrypted blob instead |
| `team.enc.json` | Safe to commit — ciphertext, useless without the key |

---

## Managing the team dossier

### 1. Create your roster (once)

```bash
cp team.private.example.json team.private.json
```

Edit `team.private.json` with the real team. Every field is optional except
`name` and `role` — anything you leave blank is simply omitted from the card.

Photos: drop them in `photos/` and reference them as `"photo": "photos/name.jpg"`.
The encrypt script reads them from disk and embeds them **inside the encrypted
blob**, so no photo is ever served as a public file. Leave `photo` empty and the
card falls back to a coloured initials avatar.

### 2. Encrypt it

```bash
node tools/encrypt.mjs                    # generates a key for you
node tools/encrypt.mjs "your-own-key"     # or set your own
```

This writes `team.enc.json` and prints the access key and the share link:

```
https://voliotech.com/team.html#k=harbor-cobalt-lantern-4417
```

**Save the key — it is not stored anywhere.** Re-run the script any time to
generate a fresh one.

### 3. Publish

```bash
git add team.enc.json && git commit -m "Update team roster" && git push
```

---

## The on/off switch

There is no toggle in a settings panel — **the link itself is the switch.**

| Action | How |
|---|---|
| **On** | Send the client `team.html#k=<key>` |
| **Off** | Don't send it. The page shows only a lock screen. |
| **Revoke everyone** | Re-run `encrypt.mjs` with a new key and push. Every old link dies instantly. |

The part of the URL after `#` is a **fragment**: browsers never transmit it in
the request, so the key never appears in server logs, CDN logs, analytics, or
`Referer` headers sent to other sites. The page also strips the key from the
address bar the moment it unlocks, so screenshots don't leak it.

`team.enc.json` being public is harmless — it's AES-GCM-256 ciphertext with a
250,000-round PBKDF2-SHA256 key derivation. Without the key it's noise.

**What this protects against:** the page URL being guessed, crawled, indexed, or
forwarded. **What it doesn't:** a client who has the key choosing to share it.
Treat it like a document you emailed — because that's the trust model.

---

## Local development

`team.html` fetches `team.enc.json`, which browsers block on `file://`. Serve it
over HTTP instead:

```bash
python3 -m http.server 8099
open "http://127.0.0.1:8099/team.html#k=your-key"
```

`index.html` opens fine directly from disk.

---

## Printing to PDF

Once unlocked, **Save as PDF** in the header. The print stylesheet drops the
navigation, filters and dark backgrounds, and keeps each member card from
splitting across pages — so it drops straight into a proposal document.

Set `org.preparedFor` in `team.private.json` to stamp the client's name on the
dossier and the PDF filename.
