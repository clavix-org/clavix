# Code signing policy

Free code signing provided by [SignPath.io](https://about.signpath.io),
certificate by [SignPath Foundation](https://signpath.org).

> **Status:** application to the SignPath Foundation program pending.
> Until it is approved, Windows release binaries are **not** signed and
> SmartScreen warns on first launch. This page describes the policy that
> will apply from the first signed release onward.

## What gets signed

Only the Windows release bundles that the
[release workflow](.github/workflows/release.yml) builds from a tagged
commit of this repository:

- the MSI installer (`clavix_<version>_x64_en-US.msi`);
- the NSIS installer (`clavix_<version>_x64-setup.exe`);
- the `clavix.exe` executable they contain.

Nothing built on a developer's machine is ever signed. Development builds
(`dev-build.yml`), pull request builds, and binaries from forks are not
signed either.

Third-party binaries are not signed with this certificate. Clavix ships
none: every Windows binary in the bundle is compiled from the sources in
this repository and its locked Rust and npm dependencies.

Every release bundle, on every platform, also carries a Sigstore build
provenance attestation, which you can check with:

```bash
gh attestation verify <file> --repo clavix-org/clavix
```

## How a release gets signed

1. A release is cut by merging the release-please pull request, which
   creates the version tag.
2. GitHub Actions builds the bundles from that tag on GitHub-hosted
   runners.
3. The workflow submits the unsigned Windows bundles to SignPath, which
   checks that they come from that workflow run of this repository.
4. An approver reviews the signing request and approves it manually in
   SignPath. No release is signed without that approval.
5. SignPath returns the signed files, which the workflow attaches to the
   GitHub release.

The SignPath artifact configuration enforces the product name and
version metadata of every signed file, so a signature cannot be applied
to a binary that does not identify itself as that Clavix release.

## Team roles

| Role | Members |
| --- | --- |
| Committers and reviewers | [Upellift99](https://github.com/Upellift99) |
| Approvers | [Upellift99](https://github.com/Upellift99) |

- **Committers** may push to this repository. Every change to `master`
  goes through a pull request and the required CI checks.
- **Reviewers** review pull requests from contributors who are not
  committers before they are merged.
- **Approvers** approve each signing request in SignPath and decide
  whether a release may be signed.

Every team member uses multi-factor authentication on GitHub and on
SignPath.

## Privacy policy

Clavix collects no telemetry, analytics or crash reports, and has no
account or server of its own. It makes network requests only to:

- **The Vaultwarden or Bitwarden server you configure**, to log in,
  sync and edit your vault, and to load website icons from that server's
  `/icons` endpoint. Your vault is encrypted on your device before it is
  sent; the server never sees your master password or any secret in clear
  text.
- **Have I Been Pwned** (`api.pwnedpasswords.com`), only when you run the
  security audit. Clavix sends the first 5 characters of each password's
  SHA-1 hash (k-anonymity) and compares the results locally; the
  passwords and their full hashes never leave your device.
- **GitHub** (`api.github.com`), once at startup, to check whether a newer
  release exists. The request carries no data about you or your vault
  beyond what any HTTP request reveals (IP address, the `Clavix/<version>`
  user agent). Builds made for Linux distributions and Flatpak do not
  include this check.

This program will not transfer any other information to other networked
systems unless specifically requested by the user or the person
installing or operating it.

## Reporting a problem

If you find a binary signed with this certificate that was not built
from this repository, or suspect misuse of the signing process, report it
privately as described in [SECURITY.md](SECURITY.md).
