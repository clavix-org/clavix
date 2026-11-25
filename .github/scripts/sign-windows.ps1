# Sign command the release workflow hands to Tauri (bundle.windows.signCommand):
# Tauri calls it once per file while bundling - clavix.exe, the NSIS
# uninstaller, then each installer - with the file path as its only argument.
#
# ssign signs PE files in place with the Certum SimplySign cloud certificate,
# reading CERTUM_EMAIL and CERTUM_OTP from the environment. It cannot sign an
# MSI, so that one is left alone here and signed by the workflow's
# "Sign the Windows MSI" job instead.
param(
  [Parameter(Mandatory = $true)][string]$Path
)
$ErrorActionPreference = 'Stop'

if ([IO.Path]::GetExtension($Path) -ieq '.msi') {
  Write-Host "sign-windows: leaving $Path for the MSI signing job"
  exit 0
}

if (-not $env:SSIGN_EXE) {
  Write-Host '::error::SSIGN_EXE is not set.'
  exit 1
}

& $env:SSIGN_EXE --name 'Clavix' --url 'https://clavix.org' $Path
exit $LASTEXITCODE
