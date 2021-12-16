# OIO SAML 3 (Artifact ID: oiosaml3.java)

## 3.1.1 (planned)
- NLRFIM-120: Support SOAP bindings in Java OIO SAML 3
- NLRFIM-121: Session handling and storage in Java OIO SAML 3

## 3.1.0 (planned)
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
