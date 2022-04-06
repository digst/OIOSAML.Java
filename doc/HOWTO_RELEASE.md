# Releasing to Sonatype/public maven repositories

## Setting up pre-requisites

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

### Import Digitaliseringsstyrelsens private key to new deployers machine

`gpg --import <path_to_key>/private.key`

enter passphrase (same as the one used whhen releaseing)

### Setup sonatype repository credentials


## Build and upload release

### Upload new release using mvn

NB! Make sure that versions has been set to a non-SNAPSHOT version. Snapshot versions are uploaded with any user aproval/decline actions.

`cd oiosaml`
`mvn clean install deploy -Psign -DskipTests`

### Release on oss.sonatype.org

1. Go to https://oss.sonatype.org/#stagingRepositories and login
2. Observe that a staging repository version has been uploaded.
3. Select the version and click "Close" (= ready for release).
4. Wait for Sonatype making some tests/inspections off the version
5. When this has succeeded select the version and click "Release"

Now the version is uploaded to public maven repositories. This can take a couple of days. 
You can check here https://mvnrepository.com/artifact/dk.digst/oiosaml3.java to see if has been done.