# macOS signing setup

The release workflow signs the macOS bundles with an Apple Developer ID,
notarizes them with Apple, and staples the notarization ticket, so
Gatekeeper opens Clavix without a warning. Tauri does the work; the
workflow only needs six repository secrets. This page explains how a
maintainer creates them.

Only the holder of the Apple Developer account can run these steps: they
involve the account's private signing key and credentials.

## What you need

- A paid Apple Developer Program membership. Only the **Account Holder**
  can create a Developer ID certificate.
- A Mac with Keychain Access for steps 1 to 3, which create and export
  the private key.
- The GitHub CLI (`gh`), signed in with admin rights on
  `clavix-org/clavix`. Steps 4 and 5 also work on Linux, with the
  variants given there.

## 1. Create a certificate signing request (CSR)

1. Open Keychain Access. Since macOS Sequoia it is no longer in
   Applications > Utilities; open it from Spotlight or with:

   ```bash
   open "/System/Library/CoreServices/Applications/Keychain Access.app"
   ```

   The Passwords app cannot generate a CSR.

2. In the menu bar: **Keychain Access > Certificate Assistant > Request a
   Certificate From a Certificate Authority**.
3. Fill in:
   - **User Email Address:** the Apple Developer account's email.
   - **Common Name:** any label you will recognize the key by, such as
     `Clavix Developer ID`. Apple does not copy it into the certificate.
   - **CA Email Address:** leave empty.
   - **Request is:** *Saved to disk*.
   - Leave *Let me specify key pair information* unchecked (RSA 2048 is
     the right default).
4. Save the `.certSigningRequest` file.

The private key is created in your login keychain at this point. It never
leaves the Mac until you export it in step 3.

## 2. Create the Developer ID Application certificate

1. On developer.apple.com, go to **Certificates, Identifiers & Profiles >
   Certificates** and click **+**.
2. Under **Software**, choose **Developer ID Application**. Not
   *Developer ID Installer* (that signs `.pkg` files, and Clavix ships a
   `.dmg`), not *Apple Development* or *Apple Distribution* (those are for
   development and the Mac App Store), and nothing under *Services*.
3. If asked for a profile type, choose **G2 Sub-CA**.
4. Upload the CSR from step 1, then download the `.cer` file.
5. Double-click the `.cer` to add it to your login keychain.

In Keychain Access, under **My Certificates**, the certificate now shows
a disclosure triangle with the private key under it. If there is no key
under it, the CSR was made on another Mac or in another keychain: start
again from step 1 on this Mac.

## 3. Export the certificate as a `.p12`

1. In Keychain Access, **My Certificates**, right-click
   *Developer ID Application: …* and choose **Export**.
2. Save it as a `.p12` file (Personal Information Exchange), for example
   `~/Desktop/developer-id.p12`.
3. Set a strong password when asked. You need it for
   `APPLE_CERTIFICATE_PASSWORD`.

## 4. Gather the other values

- **Signing identity:** the certificate's full name, like
  `Developer ID Application: Your Name (ABCDE12345)`.
- **Team ID:** the 10 characters in parentheses at the end of the
  identity. It is also shown on developer.apple.com under **Membership**.
- **App-specific password:** on account.apple.com, **Sign-In and
  Security > App-Specific Passwords**, create one named for example
  `Clavix notarization`. Notarization uses it in place of your Apple
  Account password, and you can revoke it on its own.

The commands below extract the identity and the Team ID into shell
variables, which step 5 sends straight to GitHub. Run the one that
matches your system, in the same terminal you will use for step 5.

On macOS, from the keychain:

```bash
identity=$(security find-identity -v -p codesigning | sed -n 's/.*"\(Developer ID Application: .*\)"/\1/p')
```

On Linux, `security` does not exist; read the certificate with OpenSSL
instead, either from the `.cer` downloaded in step 2:

```bash
identity=$(openssl x509 -inform DER -in developerID_application.cer -noout -subject -nameopt RFC2253 | sed -n 's/.*CN=\(Developer ID Application: .*([A-Z0-9]\{10\})\).*/\1/p')
```

or from the `.p12` exported in step 3 (it asks for the export
password; OpenSSL 3 needs `-legacy` because Keychain Access exports
with older ciphers, drop it on OpenSSL 1.1):

```bash
identity=$(openssl pkcs12 -in developer-id.p12 -nokeys -legacy | openssl x509 -noout -subject -nameopt RFC2253 | sed -n 's/.*CN=\(Developer ID Application: .*([A-Z0-9]\{10\})\).*/\1/p')
```

Then, on either system, take the Team ID from the identity and check
both values:

```bash
team_id=$(printf '%s' "$identity" | sed -n 's/.*(\([A-Z0-9]\{10\}\))$/\1/p')
```

```bash
printf 'identity: %s\nteam id:  %s\n' "$identity" "$team_id"
```

Each line must show exactly one value. If `identity` is empty, the
certificate is missing or is not a Developer ID Application one. If it
spans several lines, the keychain holds more than one Developer ID
Application certificate: keep the current one and delete or ignore the
others before going on.

## 5. Create the repository secrets

| Secret | Value |
| --- | --- |
| `APPLE_CERTIFICATE` | The `.p12` file, base64-encoded |
| `APPLE_CERTIFICATE_PASSWORD` | The `.p12` export password from step 3 |
| `APPLE_SIGNING_IDENTITY` | The full identity from step 4 |
| `APPLE_ID` | The Apple Developer account's email |
| `APPLE_PASSWORD` | The app-specific password from step 4 |
| `APPLE_TEAM_ID` | The Team ID from step 4 |

The certificate is encoded and sent in one pipe, with no intermediate
file:

```bash
base64 -i ~/Desktop/developer-id.p12 | gh secret set APPLE_CERTIFICATE -R clavix-org/clavix
```

On Linux, GNU `base64` has no `-i` option and wraps its output every 76
characters; `-w0` keeps it on one line:

```bash
base64 -w0 developer-id.p12 | gh secret set APPLE_CERTIFICATE -R clavix-org/clavix
```

The identity and the Team ID come from the variables of step 4.
`printf '%s'` sends them without a trailing newline:

```bash
printf '%s' "$identity" | gh secret set APPLE_SIGNING_IDENTITY -R clavix-org/clavix
```

```bash
printf '%s' "$team_id" | gh secret set APPLE_TEAM_ID -R clavix-org/clavix
```

For the last three, run each command without a value. `gh` then asks
for it with masked input, so it stays out of your shell history:

```bash
gh secret set APPLE_CERTIFICATE_PASSWORD -R clavix-org/clavix
```

```bash
gh secret set APPLE_ID -R clavix-org/clavix
```

```bash
gh secret set APPLE_PASSWORD -R clavix-org/clavix
```

Then delete the `.p12` file. The certificate and its key stay in your
keychain if you need to export them again:

```bash
rm ~/Desktop/developer-id.p12
```

**All six or none.** With no Apple secret set, the workflow builds
unsigned macOS bundles and logs a warning. With only some of them set, it
fails the release and names the missing ones, so a half-configured setup
never ships an unsigned build by accident.

## 6. Check the first signed release

The release job's **Verify macOS signature and notarization** step runs
`codesign --verify`, `xcrun stapler validate` and `spctl --assess` on the
bundle, and fails the job if any of them fails. On a Mac, after
downloading the `.dmg`, the same check is:

```bash
spctl --assess --type execute --verbose=4 /Applications/clavix.app
```

It should print `accepted` and `source=Notarized Developer ID`. Also
open the TOTP QR scanner once: it is the only feature that needs an
entitlement (`com.apple.security.device.camera`, in
`src-tauri/Entitlements.plist`).

## Renewal

- A Developer ID Application certificate is valid for 5 years. Apps
  signed and notarized before it expires keep opening after that.
- When the certificate is renewed, or the app-specific password is
  revoked, redo the steps that changed and update the matching secrets.
- If the membership lapses, notarization stops working and the release
  job fails at the signing step. Renewing the membership is enough; the
  certificate does not need to be recreated.
