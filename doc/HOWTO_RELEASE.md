# Releasing OIOSAML.Java to Maven Central

Only the library module, `oiosaml` (artifact `dk.digst:oiosaml3.java`), is published. The demo, test IdP and integration test modules are not deployed: the root POM sets `maven.deploy.skip`. Publishing goes through Sonatype's OSSRH Staging API into the Central Portal (https://central.sonatype.org/publish/publish-portal-ossrh-staging-api/).

## Prerequisites (once per release manager)

### Central Portal access

1. Sign in at https://central.sonatype.com. Sonatype's old OSSRH accounts at `issues.sonatype.org` are retired.
2. Get publishing rights for the `dk.digst` namespace. The Central Portal has no self-service invite: an existing `dk.digst` publisher asks Central Support (https://central.sonatype.org/pages/support/) to add your Portal username, writing from the email address of their own publisher account. The namespace is verified, so Sonatype reviews the request by hand; allow a few days.
3. Generate a **Portal user token** (https://central.sonatype.com/usertoken) and add it to `~/.m2/settings.xml`. The server id must be `ossrh`, as in `distributionManagement` in `oiosaml/pom.xml`:

```xml
<settings>
    <servers>
        <server>
            <id>ossrh</id>
            <username>[token username]</username>
            <password>[token password]</password>
        </server>
    </servers>
</settings>
```

A Sonatype login, or a token from the retired OSSRH service, is answered with `401`.

### GnuPG and the signing key

Install GnuPG (Windows: https://gpg4win.org/download.html; macOS: `brew install gnupg`, then add `export GPG_TTY=$(tty)` to your shell profile).

Artifacts are signed with Digitaliseringsstyrelsen's release key. Export it from the current release manager's machine and import it on the new one; both prompt for the key's passphrase:

```bash
gpg --list-secret-keys
gpg --export-secret-keys > private.key      # current release manager
gpg --import <path_to_key>/private.key      # new release manager
```

Delete `private.key` after the import.

### JDK

Build with **JDK 11 or later**, as CI does. The POMs compile with `--release 8`, which JDK 8 cannot run. The library still runs on Java 8.

## Release

The steps use `3.3.0` as the example; replace it with the version being released. The version does not follow the OIOSAML profile version; see the table in `README.md`.

### 1. Prepare the release on a branch

On a feature branch named after the Jira issue (e.g. `feature/REF-nn-release-3.3.0`):

```bash
mvn versions:set -DnewVersion=3.3.0 -DprocessAllModules=true -DgenerateBackupPoms=false
```

This sets the version in all five POMs. Then:

- complete the `3.3.0` entry in `RELEASE_NOTES.md`, including upgrade notes for anything that is not backwards compatible;
- update the version table and the dependency snippet in `README.md`.

Open a pull request and merge it into `master` once CI is green.

### 2. Tag the release

```bash
git checkout master && git pull
git tag -a 3.3.0 -m "OIOSAML.Java 3.3.0"
git push origin 3.3.0
```

### 3. Build, test and deploy from the tag

```bash
git checkout 3.3.0
mvn -B clean install                 # builds every module and runs the tests
cd oiosaml
mvn -B deploy -Psign -DskipTests     # tests ran in the previous step
```

`-Psign` signs the jar, sources jar, javadoc jar and POM. Make sure the version is not a `-SNAPSHOT`: snapshots go to the snapshot repository without any review (if snapshots are enabled for `dk.digst` in the Central Portal; otherwise the deploy fails).

### 4. Publish on Sonatype

The deploy leaves the artifacts in a staging repository. The manual endpoints authenticate with the Portal user token as a bearer token:

```bash
TOKEN=$(printf '%s:%s' '<token username>' '<token password>' | base64 | tr -d '\n')
```

1. Find the repository key:
   ```bash
   curl -H "Authorization: Bearer $TOKEN" "https://ossrh-staging-api.central.sonatype.com/manual/search/repositories?ip=any&profile_id=dk.digst"
   ```
   ```json
   {
     "repositories": [
       {
         "key": "<USERNAME>/<IP>/dk.digst--default-repository",
         "state": "open",
         "description": null,
         "portal_deployment_id": null
       }
     ]
   }
   ```
2. Move the staging repository to the Central Portal for review:
   ```bash
   curl -H "Authorization: Bearer $TOKEN" -X POST -F "publishing_type=user_managed" -F "deployment_name=OIOSAML.Java-3.3.0" "https://ossrh-staging-api.central.sonatype.com/manual/upload/repository/<REPO KEY>"
   ```
3. Open https://central.sonatype.com/publishing/deployments, check the content of the deployment and press **Publish**.

The release reaches Maven Central within minutes to hours; https://mvnrepository.com/artifact/dk.digst/oiosaml3.java may take a few days.

If the staging repository holds the wrong content, drop it before publishing:

```bash
curl -H "Authorization: Bearer $TOKEN" -X DELETE "https://ossrh-staging-api.central.sonatype.com/manual/drop/repository/<REPO KEY>"
```

### 5. After the release

- Optionally, create a GitHub release for the tag with the release notes.
- On a new branch, move `master` to the next development version, e.g. `mvn versions:set -DnewVersion=3.3.1-SNAPSHOT -DprocessAllModules=true -DgenerateBackupPoms=false`, and merge it through a pull request.
