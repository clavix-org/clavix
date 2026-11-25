# Windows signing setup

The release workflow can sign the Windows bundles with a
[Certum Open Source Code Signing](https://shop.certum.eu/open-source-code-signing-on-simplysign.html)
certificate, so SmartScreen and UAC name a publisher instead of warning
about an unknown one. The private key stays in Certum's SimplySign
cloud; the workflow logs in there and has each file signed.

The workflow steps are in place and stay inactive until the repository
holds the two secrets below. This page explains how a maintainer gets
them. The public rules that apply to signing are in
[CODE_SIGNING.md](CODE_SIGNING.md).

> **Not run yet.** These steps were written before the certificate
> existed. Step 3 is the first real test; expect to adjust the workflow
> on the first release.

## How it works

Certum only documents signing through its SimplySign Desktop
application, which needs someone to type a one-time code. The workflow
uses [ssign](https://github.com/Le-Syl21/ssign) instead, a third-party
open source client for the same cloud service. It is not affiliated with
Certum, and it is the piece that sees the signing credentials, so the
workflow downloads a fixed version and checks its SHA-256 before running
it.

- **On the Windows runner**, Tauri calls
  [`.github/scripts/sign-windows.ps1`](.github/scripts/sign-windows.ps1)
  for each file while bundling: `clavix.exe` before it is packed, the
  NSIS uninstaller, then the NSIS installer. `ssign` signs them.
- **On a Linux runner**, the "Sign the Windows MSI" job signs the MSI
  with `osslsigncode` and ssign's PKCS#11 module, because `ssign` itself
  only handles `.exe` and `.dll` files.

Both jobs check the signatures before anything is attached to the
release.

## 1. Buy and activate the certificate

Only the person whose name will be on the certificate can do this.

1. Order *Open Source Code Signing* (the SimplySign cloud version, not
   the one on a card) at
   <https://shop.certum.eu/open-source-code-signing-on-simplysign.html>.
2. Go through Certum's identity check. It asks for an identity document,
   a utility bill in your name, and the URL of the project, which must
   show your link to it
   (<https://support.certum.eu/en/code-signing-required-documents/>).
3. Install the SimplySign app on a phone and activate it with the QR
   code Certum provides.

**Keep the QR code's content when you activate.** It holds an
`otpauth://totp/...` URI whose `secret=` value is the TOTP seed, and the
workflow needs it. Scan the QR code with an authenticator or password
manager that can show the secret (or decode a screenshot with
`zbarimg`), in addition to the SimplySign app. If you only scan it with
the SimplySign app, the seed is gone and the QR code has to be re-issued
by Certum.

The certificate is for non-commercial open source software only: Certum
revokes it if it signs software that is sold.

## 2. Store the secrets in GitHub

```bash
gh secret set CERTUM_EMAIL --repo clavix-org/clavix
gh secret set CERTUM_OTP --repo clavix-org/clavix
```

Each command prompts for the value, which keeps it out of the shell
history.

- `CERTUM_EMAIL`: the e-mail address of the Certum account.
- `CERTUM_OTP`: the TOTP seed (base32), or the whole `otpauth://` URI.

**The seed is as sensitive as a private key.** Together with the e-mail
address, it lets anyone sign software in your name until Certum
re-issues the QR code. If it leaks, have the QR code re-issued and set
the secret again.

With neither secret set, the workflow builds unsigned bundles, as it
does on forks. With only one, the Windows job fails and names the other.

## 3. Check the certificate before a release

On your own machine, with a 6-digit code read from the SimplySign app,
so the seed is not involved. Download `ssign` from its
[releases](https://github.com/Le-Syl21/ssign/releases) and an installer
from a past Clavix release, then:

```bash
ssign -e you@example.com -T 123456 clavix_<version>_x64-setup.exe
osslsigncode verify -CAfile /etc/ssl/certs/ca-certificates.crt \
  -TSA-CAfile /etc/ssl/certs/ca-certificates.crt \
  -in clavix_<version>_x64-setup.exe
```

`ssign` runs on Linux, macOS and Windows. If this works, the account,
the certificate and the tool are fine, and what remains to be proven is
the workflow itself.

## 4. At each release

Nothing more than merging the release-please pull request. The Windows
job signs and verifies `clavix.exe` and the NSIS installer and publishes
the installer; the "Sign the Windows MSI" job then signs, verifies and
publishes the MSI.

If signing fails, the release has no Windows installers (or no MSI);
Linux and macOS are unaffected. Re-run the failed job from the Actions
page.

SmartScreen builds reputation per certificate: the first signed releases
may still show a warning, now naming the publisher, until enough
downloads have accumulated.

## Updating ssign

The version and checksums are pinned in
[`release.yml`](.github/workflows/release.yml): `SSIGN_VERSION` and
`SSIGN_SHA256` in the build job, `SSIGN_VERSION`, `MODULE_SHA256` and
`INTERMEDIATE_SHA256` in the "Sign the Windows MSI" job. Read the
changes between the two versions before bumping: this tool handles the
signing credentials.

## Renewal

The certificate has an expiry date. Files signed before it stay valid,
because every signature is timestamped. After renewing, check whether
Certum issued a new QR code, and update `CERTUM_OTP` if so.
