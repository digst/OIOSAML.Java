# OIO SAML 3 (Artifact ID: oiosaml3.java)

## 3.3.1 (unreleased)

### Fixes
- REF-84: OIOBPP privileges are read whichever form the JAXB implementation returns them in. With some JAXB implementations parsing failed with a `ClassCastException`, so `AssertionWrapper.getPrivilegeList()` returned null (issue #68).

## 3.3.0
A security-hardening release. It is **not a drop-in replacement for 3.2.x**; read *Upgrading from 3.2.x* below before deploying.

### Security
- REF-26: The assertion signature must be bound to the assertion being consumed (SAML signature profile validation).
- REF-28: Incoming LogoutRequests must be signed by the configured IdP (XML signature or HTTP-Redirect query-string signature).
- REF-29: Assertion decryption accepts only the algorithms in [OIO-ALG-01].
- REF-30: The session id changes when a login is accepted.
- REF-31: CRLs and OCSP responses are verified before they are trusted, and an issuing CA certificate fetched for revocation checking must have issued the certificate being checked.
- REF-32: Document type declarations are rejected when parsing OIOBPP privileges, and the JAXB runtime is replaced.
- REF-33: IdP metadata is read from a deployed file, and a signature made with any signing certificate published in it is accepted, so the IdP can rotate its signing key without an SP outage.
- REF-47: When a professional identity is requested (`oiosaml.filter.attribute.profile`), the assertion's NameID must be a professional identifier. Previously only a person request had its NameID checked.
- REF-65:
  - Incoming LogoutResponses must answer the LogoutRequest sent from the session, come from the configured IdP, be signed by it and name this SP's logout response endpoint as Destination.
  - The assertion must be bound to the AuthnRequest by the signed `SubjectConfirmationData/@InResponseTo` (SAML profiles 4.1.4.2); the unsigned `Response/@InResponseTo` alone is no longer sufficient.
  - The default error page renders error messages as text.
  - IdP certificates are checked for revocation again every hour while the SP runs, not only when the metadata file changes. A check that validates no signing certificate is retried after a minute instead of blocking login until restart. A certificate stops being trusted as soon as it expires, also with revocation checking disabled.
  - The database session handler claims an assertion ID before storing the assertion, so a given assertion is accepted for one session only, also under concurrent requests.
  - `SessionNotOnOrAfter` from the IdP is enforced for the whole session with the in-memory session handler, not only at login.

### Other changes
- REF-5, REF-17: GitHub Actions build with a published test report.
- REF-6: The keystore alias is resolved case-insensitively.
- REF-7: Resource names in subdirectories are handled when copying non-file URLs to a temporary file.
- REF-8: Fixed a seconds/milliseconds mix-up in in-memory session cleanup.
- REF-14: The Word documentation is converted to Markdown and merged into README.md.
- REF-15: The default audit attribute sources for `SESSION_ID` and `USER` were transposed and are corrected.
- REF-16: OCSP requests are sent using POST (`oiosaml.servlet.revocation.ocsp.post.enabled`, default `true`).
- REF-18: Updated NemLog-in DevTest4 IdP metadata in the demo.
- REF-27: The value of the `SpecVer` attribute is no longer validated, only its presence, so assertions issued under OIOSAML 4.0 are accepted.
- REF-65: Unit tests no longer depend on the order in which test classes run.
- REF-65: The demo SP uses a current OCES3 test certificate (`OIOSAML.Java SP and WSC`, valid until 2029-09-01); the previous one expired on 2026-08-17.

### Upgrading from 3.2.x
- **IdP metadata must be a deployed file.** `oiosaml.servlet.idp.metadata.url` is no longer supported: download the IdP metadata, deploy it, and point `oiosaml.servlet.idp.metadata.file` at it. If only the URL is configured, the servlet refuses to start; if both are configured, the URL is ignored with a warning. Use an absolute filesystem path, so a replaced file takes effect without a redeploy.
- **`oiosaml.servlet.trust.selfsigned.certs=true` is no longer supported** and stops the servlet from starting. It only applied to fetching metadata over HTTPS.
- **Servlet 3.1 or later is required** (`HttpServletRequest.changeSessionId()`). On a Servlet 3.0 container the application deploys, but every login fails.
- **The session id changes at login.** Application state keyed on the session id from before login must not rely on it surviving login.
- **Logout messages must be signed by the IdP.** Incoming LogoutRequests and LogoutResponses that are unsigned, signed with a key not in the IdP metadata, or not from the configured IdP are rejected. A LogoutResponse must also answer the LogoutRequest sent from the same browser session.
- **Assertions must carry `SubjectConfirmationData/@InResponseTo`** equal to the AuthnRequest ID, as SAML 2.0 requires of responses to an AuthnRequest. Custom or test IdPs must set it.
- **Assertion decryption is limited to [OIO-ALG-01]:** RSA-OAEP key transport with AES-128/256-CBC or AES-128/192/256-GCM. RSA 1.5, 3DES and AES-192-CBC are rejected.
- **IdP certificate checks are stricter.** Certificates outside their validity period are rejected, also with OCSP and CRL disabled. A definitive OCSP failure is no longer overridden by a CRL check, and CRLs must be signed by the issuing CA and be current.
- **`oiosaml.servlet.revocation.ocsp.post.enabled`** (default `true`) sets the JVM-wide system property `com.sun.security.ocsp.useget=false` unless it is already set.
- **Audit log:** the default sources for `SESSION_ID` and `USER` are swapped back to `request:sessionId` and `request:remoteUser`. Consumers of the audit log will see different values in these fields.
- **Public API changes:**
  - `Configuration`: the metadata URL and self-signed accessors are removed.
  - `Constants.IDP_METADATA_URL` and `SUPPORT_SELF_SIGNED` are renamed to `REMOVED_*`, and `SPEC_VER_VAL` is removed.
  - `IdPMetadata` is constructed with `(entityId, metadataFile)`, and `getValidX509Certificate(UsageType)` is replaced by `getValidX509Certificates(UsageType)`.
  - `CRLChecker.checkCertificates(List)` changed; `CRLChecker.isWithinValidityPeriod` is now public.
  - `LogoutRequestService.validateLogoutRequest(...)` and `LogoutResponseService.validateLogoutResponse(...)` are now static and take the request and message.
- **Dependencies:** `com.sun.xml.bind` JAXB is replaced by `org.glassfish.jaxb:jaxb-runtime` 2.3.9. The database schema is unchanged.

## 3.2.2
- NLRFIM-213: bump version of hsqldb to 2.7.1 and updated tests

## 3.2.1
- NLRFIM-168: Support AppSwitch extension on AuthnRequest in Java OIO SAML 3

## 3.2.0
- NLRFIM-120: Support SOAP bindings in Java OIO SAML 3
- NLRFIM-121: Session handling and storage in Java OIO SAML 3
- NLRFIM-123: Replay protection in Java OIO SAML 3
- CVE-2021-45105, CVE-2021-44832: Update log4j-core to version 2.17.1
- NLRFIM-153: Fail when trying to load configured credentials and private key is missing
- NLRFIM-139: Absolute path OIOSAML configuration

## 3.1.0
- CVE-2021-44228: Update log4j-core to version 2.16.0
- NLRFIM-109: Logging for Java OIO SAML 3

## 3.0.2
- NLRFIM-124: ResponseLocation is optional cf. section 2.2.2 in OASIS SAML 2 Metadata and hence if attribute is not present NULL check must be performed.
- NLRFIM-125: Missing KeyInfo in XML signature.
- NLRFIM-115: Custom URL paths in Java
- NLRFIM-130: Store query parameters in session when redirecting to IdP.
- NLRFIM-128: Update local IDP stub to fix runtime problems in the demo
- NLRFIM-110: Java OIO SAML 3 clock controls seconds instead of minutes

## 3.0.1
First official release based on OpenSAML 3.

# OIO SAML 2 (Artifact ID: oiosaml2.java)

## 2.1.2
- NLRFIM-100: Patch security issues in OIO SAML 2 version based on OpenSAML 2.6 (https://nvd.nist.gov/vuln/detail/CVE-2015-7501 and https://nvd.nist.gov/vuln/detail/CVE-2013-5960)
- NLRFIM-126: Dead lock in session handling (https://www.digitaliser.dk/forum/6259878)

## 2.1.1
Stable OIO SAML 2 reference implementation.
