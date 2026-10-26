#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"

Push-Location

Set-Location $PSScriptRoot

Write-Host "Installing the demo TLS certificate"
$certificate = Import-Certificate -FilePath '.\ssl-demo.cer' -CertStoreLocation Cert:\LocalMachine\Root
Write-Host "Installed the self-signed localhost certificate $($certificate[0].Thumbprint) in LocalMachine\Root. This makes the demo SP and the demo IdP (ssl-demo.pfx) trusted on your machine and browser"

Write-Host "Setup completed!"

Pop-Location
