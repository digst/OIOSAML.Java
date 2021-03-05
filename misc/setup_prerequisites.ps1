#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"

Push-Location

Set-Location $PSScriptRoot

Write-Host "Installing CA certificate"
$rootCertificate = Import-Certificate -FilePath '.\myca.cer' -CertStoreLocation Cert:\LocalMachine\Root
Write-Host "Installed CA certificate $($rootCertificate[0].Thumbprint) in LocalMachine\Root. This ensures the used SSL/TLS certificate is trusted on your machine and browser"

Write-Host "Setup completed!"

Pop-Location
