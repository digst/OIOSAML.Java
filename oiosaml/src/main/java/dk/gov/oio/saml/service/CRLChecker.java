package dk.gov.oio.saml.service;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertPathValidatorException.BasicReason;
import java.security.cert.PKIXParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.i18n.filter.UntrustedUrlInput;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.joda.time.DateTime;
import org.opensaml.core.config.InitializationException;

import dk.gov.oio.saml.config.Configuration;
import dk.gov.oio.saml.util.ExternalException;
import dk.gov.oio.saml.util.InternalException;

public class CRLChecker {
    private static final Logger log = LoggerFactory.getLogger(CRLChecker.class);
    private static final String AUTH_INFO_ACCESS = Extension.authorityInfoAccess.getId();

    // JDK system property deciding whether the built-in OCSP client may use the RFC 5019 GET form
    // (request base64-encoded into the URL path) for small requests, see sun.security.provider.certpath.OCSP
    private static final String JDK_OCSP_USE_GET_PROPERTY = "com.sun.security.ocsp.useget";

    // Revocation data is fetched from locations named by the certificate being checked, a slow or
    // unresponsive endpoint must not hold the revocation check open
    private static final int CONNECT_TIMEOUT_MILLIS = 10000;
    private static final int READ_TIMEOUT_MILLIS = 10000;

    private static final Map<String, X509Certificate> issuingCACertificatesByUrl = new ConcurrentHashMap<String, X509Certificate>();

    // Indexes of the keyCertSign and cRLSign bits in the KeyUsage extension, see RFC 5280 section 4.2.1.3
    private static final int KEY_CERT_SIGN = 5;
    private static final int CRL_SIGN = 6;

    /**
     * Make the JDK OCSP client POST its requests instead of using the RFC 5019 GET form.
     * <p>
     * JDK 12 and later default to GET for requests that fit in 255 characters, but the NemLog-in OCSP
     * responders answer HTTP 404 to that form. The resulting UNDETERMINED_REVOCATION_STATUS makes every
     * OCSP check fail, which silently degrades the SP to the CRL fallback, or drops the IdP certificates
     * entirely when CRL checking is disabled as well. POST is mandatory for responders (RFC 6960), so
     * forcing it is safe. Java 8 and 11 always POST and are unaffected.
     * <p>
     * The JDK reads the property once, when sun.security.provider.certpath.OCSP is initialized, so this
     * must run before the first OCSP check in the JVM, hence the call from {@link OIOSAML3Service#init}.
     * An explicit setting made by the deployer (-Dcom.sun.security.ocsp.useget=...) always wins.
     */
    static void configureOcspTransport(Configuration configuration) {
        if (!configuration.isOcspPostEnabled()) {
            log.info("Leaving '{}' untouched, OCSP POST is disabled in the OIOSAML configuration", JDK_OCSP_USE_GET_PROPERTY);
            return;
        }

        String existingValue = System.getProperty(JDK_OCSP_USE_GET_PROPERTY);
        if (existingValue != null) {
            log.info("Leaving '{}' at the value set by the deployer: {}", JDK_OCSP_USE_GET_PROPERTY, existingValue);
            return;
        }

        System.setProperty(JDK_OCSP_USE_GET_PROPERTY, "false");
        log.info("Setting '{}' to false, so OCSP requests are sent using POST", JDK_OCSP_USE_GET_PROPERTY);
    }

    public static Set<X509Certificate> checkCertificates(List<X509Certificate> x509Certificates, DateTime lastCRLCheck) throws ExternalException, InternalException, InitializationException {
        Set<X509Certificate> result = new HashSet<>();
        if (x509Certificates == null || x509Certificates.isEmpty()) {
            return result;
        }

        // Check all certificates, and return those that are valid
        for (final X509Certificate certificate : x509Certificates) {
            if (checkCertificate(certificate)) {
                result.add(certificate);
                log.debug("Certificate validated successfully: {}", certificate.getSubjectDN());
            } else {
                log.warn("Certificate did not validate: {}", certificate.getSubjectDN());
            }
        }

        return result;
    }

    // OCSP first if configured, with fallback to CRL if configured
    private static boolean checkCertificate(X509Certificate certificate) {
        if (!isWithinValidityPeriod(certificate)) {
            log.warn("Certificate is outside its validity period: {}", certificate.getSubjectDN());
            return false;
        }

        boolean validated = false;

        Configuration config = OIOSAML3Service.getConfig();
        if (config.isOcspCheckEnabled()) {
            try {
                validated = doOCSPCheck(certificate);
            } catch (Exception e) {
                if (!isRevocationDataUnavailable(e)) {
                    log.warn("Certificate rejected while validating it using OCSP: {}", certificate.getSubjectDN(), e);
                    return false;
                }

                log.warn("Unexpected error while validating certificate using OCSP.", e);

                if (config.isCRLCheckEnabled()) {
                    try {
                        validated = doCRLCheck(certificate);
                    } catch (Exception ex) {
                        log.warn("Unexpected error while validating certificate using CRL.", ex);
                    }
                }
            }
        } else if (config.isCRLCheckEnabled()) {
            try {
                validated = doCRLCheck(certificate);
            } catch (Exception ex) {
                log.warn("Unexpected error while validating certificate using CRL.", ex);
            }
        } else {
            log.warn("checkCertificate called, but both OCSP and CRL checking is disabled");
            validated = true;
        }

        return validated;
    }

    private static boolean doOCSPCheck(X509Certificate certificate) throws CertificateException, CertPathValidatorException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, URISyntaxException {
        log.debug("Starting OCSP validation of certificate {}", certificate.getSubjectDN());

        String ocspServer = getOCSPUrl(certificate);
        if (ocspServer == null) {
            throw new RuntimeException("No OCSP access location could be found");
        }

        URI responder = toHttpUri(ocspServer);

        // try to retrieve issuing OCES CA certificate
        X509Certificate issuer = getIssuingCertificate(certificate);
        if (issuer == null) {
            throw new RuntimeException("CA Certificate for OCSP check could not be retrieved!");
        }

        List<X509Certificate> certList = new ArrayList<X509Certificate>();
        certList.add(certificate);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        CertPath cp = cf.generateCertPath(certList);

        boolean revoked;
        try {
            TrustAnchor anchor = new TrustAnchor(issuer, null);
            PKIXParameters params = new PKIXParameters(Collections.singleton(anchor));

            CertPathValidator cpv = CertPathValidator.getInstance("PKIX");

            // Configure revocation checking on this validation only. The alternative, the JVM global
            // "ocsp.enable"/"ocsp.responderURL" security properties, leaks the responder of the certificate
            // being checked into every other PKIX validation in the JVM, and races with concurrent checks.
            PKIXRevocationChecker revocationChecker = (PKIXRevocationChecker) cpv.getRevocationChecker();
            revocationChecker.setOcspResponder(responder);

            // Fallback to CRL is handled by checkCertificate, according to the OIOSAML configuration
            revocationChecker.setOptions(EnumSet.of(PKIXRevocationChecker.Option.NO_FALLBACK));

            params.setRevocationEnabled(false);
            params.addCertPathChecker(revocationChecker);

            // Validate and obtain results
            cpv.validate(cp, params);

            log.debug("Certificate successfully validated during OCSP check.");
            revoked = false;
        } catch (CertPathValidatorException cpve) {
            if (BasicReason.REVOKED == cpve.getReason()) {
                revoked = true;
                log.info("Certificate revoked, cert[{}] : {}", cpve.getIndex(), cpve.getMessage());
            } else {
                log.warn("Validation failure, cert[{}] : {}", cpve.getIndex(), cpve.getMessage());
                throw cpve;
            }
        }

        return (!revoked);
    }

    /**
     * Whether the OCSP check failed because the revocation status could not be obtained, rather than because
     * the certificate itself failed validation. Only the former is a reason to ask the CRL instead: the CRL
     * says nothing about the validity of a certificate, so letting it answer for a rejected certificate
     * would turn that rejection into an acceptance.
     */
    private static boolean isRevocationDataUnavailable(Exception e) {
        if (e instanceof CertPathValidatorException) {
            return BasicReason.UNDETERMINED_REVOCATION_STATUS == ((CertPathValidatorException) e).getReason();
        }

        // Everything else is a failure, such as a certificate naming no responder
        // or an issuer certificate that could not be fetched
        return true;
    }

    private static X509Certificate getIssuingCertificate(X509Certificate certificate) {
        log.debug("Attempting to extract issuing ca certifcate from certificate {}", certificate.getSubjectDN());

        AuthorityInformationAccess authInfoAcc = null;

        try {
            byte[] bytes = certificate.getExtensionValue(AUTH_INFO_ACCESS);

            try (ASN1InputStream aIn = new ASN1InputStream(bytes)) {
                ASN1OctetString octs = (ASN1OctetString) aIn.readObject();

                try (ASN1InputStream aIn2 = new ASN1InputStream(octs.getOctets())) {
                    ASN1Primitive auth_info_acc = aIn2.readObject();

                    if (auth_info_acc != null) {
                        authInfoAcc = AuthorityInformationAccess.getInstance(auth_info_acc);
                    }
                }
            }
        } catch (Exception e) {
            log.debug("Cannot extract access location of issuing ca.", e);
            return null;
        }

        List<String> issuingCaUrls = getIssuingCAUrls(authInfoAcc);
        Iterator<String> urlIt = issuingCaUrls.iterator();
        while (urlIt.hasNext()) {
            Object caUrl = new UntrustedUrlInput(urlIt.next());
            String url = caUrl.toString();

            // A cached certificate is only reused while it still is the issuer, so that a CA replaced at the
            // same location is picked up instead of failing every check until the process restarts
            X509Certificate cached = issuingCACertificatesByUrl.get(url);
            if (cached != null && isIssuedBy(cached, certificate)) {
                return cached;
            }

            X509Certificate issuer = downloadCertificate(url);
            if (issuer == null || !isIssuedBy(issuer, certificate)) {
                return null;
            }

            issuingCACertificatesByUrl.put(url, issuer);

            return issuer;
        }

        return null;
    }

    /**
     * The AIA location is named by the certificate being checked, so the certificate downloaded from it can
     * only serve as trust anchor or CRL signer once it is known to be a CA allowed to issue certificates,
     * and to be the one that issued that certificate.
     */
    private static boolean isIssuedBy(X509Certificate issuer, X509Certificate certificate) {
        if (!certificate.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
            log.warn("Certificate fetched from the issuer location of {} is issued to somebody else", certificate.getSubjectDN());
            return false;
        }

        // Below zero means the basic constraints deny the certificate the CA role, or say nothing at all
        if (issuer.getBasicConstraints() < 0) {
            log.warn("Certificate fetched from the issuer location of {} is not a CA certificate", certificate.getSubjectDN());
            return false;
        }

        if (!hasKeyUsage(issuer, KEY_CERT_SIGN)) {
            log.warn("Certificate fetched from the issuer location of {} is not allowed to sign certificates", certificate.getSubjectDN());
            return false;
        }

        if (!isWithinValidityPeriod(issuer)) {
            log.warn("Certificate fetched from the issuer location of {} is outside its validity period", certificate.getSubjectDN());
            return false;
        }

        try {
            certificate.verify(issuer.getPublicKey());
            return true;
        } catch (GeneralSecurityException e) {
            log.warn("Certificate fetched from the issuer location of {} did not issue it", certificate.getSubjectDN(), e);
            return false;
        }
    }

    /**
     * Open a stream to a location named by certificate content.
     *
     * <p>Only http and https are allowed. The OCES CAs serve revocation data over plain http, which is fine
     * because the data is signed, but the scheme has to be constrained so that a certificate cannot make the
     * SP read from file:, jar: or any other protocol the JVM happens to support.</p>
     */
    private static InputStream openStream(String url) throws IOException {
        URL location = new URL(url);

        String protocol = location.getProtocol().toLowerCase(Locale.ROOT);
        if (!"http".equals(protocol) && !"https".equals(protocol)) {
            throw new IOException(String.format("Refusing to fetch revocation data over '%s'", protocol));
        }

        URLConnection connection = location.openConnection();
        connection.setConnectTimeout(CONNECT_TIMEOUT_MILLIS);
        connection.setReadTimeout(READ_TIMEOUT_MILLIS);

        return connection.getInputStream();
    }

    private static URI toHttpUri(String url) throws URISyntaxException {
        URI uri = new URI(url);

        String scheme = (uri.getScheme() != null) ? uri.getScheme().toLowerCase(Locale.ROOT) : "";
        if (!"http".equals(scheme) && !"https".equals(scheme)) {
            throw new RuntimeException(String.format("Refusing to use OCSP responder with scheme '%s'", scheme));
        }

        return uri;
    }

    /**
     * Whether the certificate is within its validity period, allowing for the configured clock skew the way
     * the freshness check on a CRL does.
     */
    private static boolean isWithinValidityPeriod(X509Certificate certificate) {
        long clockSkewMillis = 1000L * 60 * OIOSAML3Service.getConfig().getClockSkew();
        long now = System.currentTimeMillis();

        return certificate.getNotBefore().getTime() - clockSkewMillis <= now
                && certificate.getNotAfter().getTime() + clockSkewMillis >= now;
    }

    /**
     * A key is only usable for the purposes its certificate grants it, and a certificate stating no key
     * usage at all grants none of them.
     */
    private static boolean hasKeyUsage(X509Certificate certificate, int keyUsageBit) {
        boolean[] keyUsage = certificate.getKeyUsage();

        return keyUsage != null && keyUsage.length > keyUsageBit && keyUsage[keyUsageBit];
    }

    private static X509Certificate downloadCertificate(String url) {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            try (InputStream is = openStream(url)) {
                X509Certificate certificate = (X509Certificate) factory.generateCertificate(is);
                if (certificate != null) {
                    return certificate;
                }

                log.warn("Failed to parse certificate from {}", url);
            } catch (IOException ex) {
                log.warn("Failed to download intermediate CA certificate from {}", url);
            }
        } catch (CertificateException ex) {
            log.warn("Failed to generate certificate factory", ex);
        }

        return null;
    }

    private static String getOCSPUrl(X509Certificate certificate) {
        log.debug("Attempting to extract OCSP location from certificate {}", certificate.getSubjectDN());

        AuthorityInformationAccess authInfoAcc = null;

        try {
            byte[] bytes = certificate.getExtensionValue(AUTH_INFO_ACCESS);
            try (ASN1InputStream aIn = new ASN1InputStream(bytes)) {
                ASN1OctetString octs = (ASN1OctetString) aIn.readObject();

                try (ASN1InputStream aIn2 = new ASN1InputStream(octs.getOctets())) {
                    ASN1Primitive auth_info_acc = aIn2.readObject();

                    if (auth_info_acc != null) {
                        authInfoAcc = AuthorityInformationAccess.getInstance(auth_info_acc);
                    }
                }
            }
        } catch (Exception e) {
            log.debug("Cannot extract access location of OCSP responder.", e);
            return null;
        }

        List<String> ocspUrls = getOCSPUrls(authInfoAcc);
        Iterator<String> urlIt = ocspUrls.iterator();

        while (urlIt.hasNext()) {
            Object ocspUrl = new UntrustedUrlInput(urlIt.next());

            return ocspUrl.toString();
        }

        return null;
    }

    private static List<String> getIssuingCAUrls(AuthorityInformationAccess authInfoAccess) {
        List<String> urls = new ArrayList<String>();

        if (authInfoAccess != null) {
            AccessDescription[] ads = authInfoAccess.getAccessDescriptions();
            for (int i = 0; i < ads.length; i++) {
                if (ads[i].getAccessMethod().equals(AccessDescription.id_ad_caIssuers)) {
                    GeneralName name = ads[i].getAccessLocation();
                    if (name.getTagNo() == GeneralName.uniformResourceIdentifier) {
                        String url = ((DERIA5String) name.getName()).getString();
                        urls.add(url);
                    }
                }
            }
        }

        return urls;
    }

    private static List<String> getOCSPUrls(AuthorityInformationAccess authInfoAccess) {
        List<String> urls = new ArrayList<String>();

        if (authInfoAccess != null) {
            AccessDescription[] ads = authInfoAccess.getAccessDescriptions();
            for (int i = 0; i < ads.length; i++) {
                if (ads[i].getAccessMethod().equals(AccessDescription.id_ad_ocsp)) {
                    GeneralName name = ads[i].getAccessLocation();
                    if (name.getTagNo() == GeneralName.uniformResourceIdentifier) {
                        String url = ((DERIA5String) name.getName()).getString();
                        urls.add(url);
                    }
                }
            }
        }

        return urls;
    }

    private static boolean doCRLCheck(X509Certificate certificate) throws IOException, GeneralSecurityException, InitializationException {
        boolean revoked;

        String url = getCRLUrl(certificate);
        if (url == null) {
            throw new RuntimeException("No CRL url could be found");
        }

        X509Certificate issuer = getIssuingCertificate(certificate);
        if (issuer == null) {
            throw new RuntimeException("CA Certificate for CRL check could not be retrieved!");
        }

        try (InputStream is = openStream(url)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509CRL crl = (X509CRL) cf.generateCRL(is);

            log.debug("CRL for {}: {}", url, crl);

            validateCRL(crl, certificate, issuer);

            X509CRLEntry revokedCertificate = crl.getRevokedCertificate(certificate.getSerialNumber());
            if (revokedCertificate != null) {
                log.warn("Certificate found in revocation list " + certificate.getSubjectDN());
                revoked = true;
            } else {
                revoked = false;
            }
        }

        return !revoked;
    }

    /**
     * A CRL is fetched from a location named by the certificate itself, so the absence of a serial number in
     * it only means anything once the list is known to be signed by the issuing CA and to be current.
     */
    private static void validateCRL(X509CRL crl, X509Certificate certificate, X509Certificate issuer) throws GeneralSecurityException {
        if (!crl.getIssuerX500Principal().equals(certificate.getIssuerX500Principal())) {
            throw new CRLException("CRL was not issued by the CA that issued the certificate");
        }

        // A CA that is not allowed to sign CRLs cannot vouch for this list however well the signature verifies
        if (!hasKeyUsage(issuer, CRL_SIGN)) {
            throw new CRLException("CRL issuer is not allowed to sign CRLs, its key usage does not include cRLSign");
        }

        crl.verify(issuer.getPublicKey());

        long clockSkewMillis = 1000L * 60 * OIOSAML3Service.getConfig().getClockSkew();
        Date now = new Date();

        Date thisUpdate = crl.getThisUpdate();
        if (thisUpdate == null || thisUpdate.getTime() - clockSkewMillis > now.getTime()) {
            throw new CRLException("CRL is not valid yet, thisUpdate is " + thisUpdate);
        }

        // RFC 5280 leaves nextUpdate optional, but a list that does not say when it is superseded cannot be
        // told apart from one that was replaced long ago
        Date nextUpdate = crl.getNextUpdate();
        if (nextUpdate == null || nextUpdate.getTime() + clockSkewMillis < now.getTime()) {
            throw new CRLException("CRL is no longer current, nextUpdate is " + nextUpdate);
        }
    }

    private static String getCRLUrl(X509Certificate certificate) throws IOException {
        log.debug("Attempting to extract distribution point from certificate {}", certificate.getSubjectDN());

        byte[] val = certificate.getExtensionValue("2.5.29.31");
        if (val != null) {
            CRLDistPoint point = CRLDistPoint.getInstance(X509ExtensionUtil.fromExtensionValue(val));
            for (DistributionPoint dp : point.getDistributionPoints()) {
                if (dp.getDistributionPoint() == null) {
                    continue;
                }

                if (dp.getDistributionPoint().getName() instanceof GeneralNames) {
                    GeneralNames gn = (GeneralNames) dp.getDistributionPoint().getName();
                    for (GeneralName g : gn.getNames()) {
                        if (g.getName() instanceof DERIA5String) {
                            return ((DERIA5String) g.getName()).getString();
                        }
                    }
                }
            }
        }

        return null;
    }
}
