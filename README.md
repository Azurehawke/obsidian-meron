# Meron Mail for Obsidian

An Obsidian plugin that is the start of the Meron mail client inside Obsidian.
This first version only checks that your IMAP and SMTP settings work. The mail
view comes next.

Desktop only (Windows first).

## Install with BRAT

1. In Obsidian, install and enable **BRAT** (community plugins).
2. Open BRAT's settings and choose **Add beta plugin**.
3. Enter `Azurehawke/obsidian-meron` and confirm.
4. Enable **Meron Mail** in Community plugins.

## Settings

- IMAP: port 993, SSL/TLS.
- SMTP: port 587, STARTTLS.
- Username and password (an app password if your server offers one).
- Optional pinned certificate SHA-256 for a self-signed server certificate.

Run **Test mail server connection** from the command palette. It logs in to IMAP and SMTP
and logs out again. It downloads and sends nothing.

## Build

    npm install
    npm run build

Releases are built by GitHub Actions when a `v*` tag is pushed. The release
includes `main.js` and `manifest.json`, which BRAT needs.

## License

AGPL-3.0-only, the same license as Meron (https://github.com/nonbili/meron).
