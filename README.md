# Nota bene

Please note that the tagged version in Git does not follow the OIO SAML profile version. The correlation is described below

See content and changes of releases in [release notes](RELEASE_NOTES.md).

### OIO SAML 2 (Artifact ID: oiosaml2.java)
* OIO SAML 2.0.9: Newest Maven package release: 2.1.2 (https://mvnrepository.com/artifact/dk.digst/oiosaml2.java)
* OIO SAML 2.1.0: Newest Maven package release: 2.1.2 (https://mvnrepository.com/artifact/dk.digst/oiosaml2.java)

### OIO SAML 3 (Artifact ID: oiosaml3.java)
* OIO SAML 3.0.2: Newest Maven package release: 3.2.0 (https://mvnrepository.com/artifact/dk.digst/oiosaml3.java)

## Setup Windows SSL/TLS trust

Run the script 'misc/setup_prerequisites.ps1' from an elevated PowerShell. This installs the required CA certificate.

## Running the Integration test

To run the IntegrationTest you need to have a `chromedriver.exe` executable in the folder C:\tools\


## Releasing to Sonatype/public maven repositories

### Create Sonatype user and gain access:

1 The user can be created here https://issues.sonatype.org/secure/Signup!default.jspa
2 Make the current repository administrator request that you get access to upload releases. The current administrator can do this by creating a Jira issue in https://issues.sonatype.org ...TODO


TODO details

### Install GnuPGP 

1. Download GnuPGP https://gpg4win.org/download.html -> https://files.gpg4win.org/gpg4win-1.0.0.exe
2. Run the installer

### Export Digitaliseringsstyrelsens private key from current deployers machine

`gpg --list-secret-keys`
`gpg --export-secret-keys > private.key`

enter passphrase (same as the one used whhen releaseing)






