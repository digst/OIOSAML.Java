package dk.gov.oio.saml.util;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Mints a CA, certificates and CRLs so revocation checking can be tested against locally served, and locally
 * tampered with, revocation data instead of a live CA.
 */
public class TestPkiUtil {
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);

        return generator.generateKeyPair();
    }

    /**
     * Self signed CA certificate, the issuer of the certificates and CRLs below, holding the basic
     * constraints and key usage a CA needs to issue both.
     */
    public static X509Certificate createCaCertificate(KeyPair keyPair, String name) throws Exception {
        return createCaCertificate(keyPair, name, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign), new BasicConstraints(0));
    }

    /**
     * Self signed CA certificate with the given key usage and basic constraints, either of which is left out
     * of the certificate when null, so a CA lacking what it takes to issue certificates or CRLs can be
     * tested.
     */
    public static X509Certificate createCaCertificate(KeyPair keyPair, String name, KeyUsage keyUsage, BasicConstraints basicConstraints) throws Exception {
        return createCaCertificate(keyPair, name, keyUsage, basicConstraints, hoursFromNow(-1), hoursFromNow(24));
    }

    /**
     * Self signed CA certificate valid in the given period, so a CA that has expired, or is not valid yet,
     * can be tested.
     */
    public static X509Certificate createCaCertificate(KeyPair keyPair, String name, KeyUsage keyUsage, BasicConstraints basicConstraints, Date notBefore, Date notAfter) throws Exception {
        X500Name subject = new X500Name("CN=" + name);

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject, BigInteger.ONE, notBefore, notAfter, subject, keyPair.getPublic());
        if (basicConstraints != null) {
            builder.addExtension(Extension.basicConstraints, true, basicConstraints);
        }
        if (keyUsage != null) {
            builder.addExtension(Extension.keyUsage, true, keyUsage);
        }

        return convert(builder, keyPair);
    }

    /**
     * Certificate naming the given locations as its CRL distribution point and issuer access location, the
     * way the OCES certificates do.
     */
    public static X509Certificate createCertificate(KeyPair keyPair, String name, BigInteger serialNumber, X509Certificate caCertificate, KeyPair caKeyPair, String crlUrl, String caIssuerUrl) throws Exception {
        return createCertificate(keyPair, name, serialNumber, caCertificate, caKeyPair, crlUrl, caIssuerUrl, null, hoursFromNow(-1), hoursFromNow(24));
    }

    /**
     * Certificate naming an OCSP responder as well, and valid in the given period, so the OCSP path and a
     * certificate that has expired, or is not valid yet, can be tested. No responder is named when the OCSP
     * location is null.
     */
    public static X509Certificate createCertificate(KeyPair keyPair, String name, BigInteger serialNumber, X509Certificate caCertificate, KeyPair caKeyPair, String crlUrl, String caIssuerUrl, String ocspUrl, Date notBefore, Date notAfter) throws Exception {
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                caCertificate, serialNumber, notBefore, notAfter, new X500Name("CN=" + name), keyPair.getPublic());

        builder.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(new DistributionPoint[] {
                new DistributionPoint(new DistributionPointName(new GeneralNames(uri(crlUrl))), null, null)}));
        builder.addExtension(Extension.authorityInfoAccess, false, accessDescriptions(caIssuerUrl, ocspUrl));

        return convert(builder, caKeyPair);
    }

    private static AuthorityInformationAccess accessDescriptions(String caIssuerUrl, String ocspUrl) {
        AccessDescription caIssuers = new AccessDescription(AccessDescription.id_ad_caIssuers, uri(caIssuerUrl));
        if (ocspUrl == null) {
            return new AuthorityInformationAccess(caIssuers);
        }

        return new AuthorityInformationAccess(new AccessDescription[] {
                caIssuers, new AccessDescription(AccessDescription.id_ad_ocsp, uri(ocspUrl))});
    }

    /**
     * CRL listing the given serial numbers as revoked.
     *
     * @param signingKeyPair key the list is signed with, which is not necessarily the CA key
     * @param nextUpdate     when the list is superseded, in the past for a list that is no longer current
     */
    public static X509CRL createCrl(X509Certificate caCertificate, KeyPair signingKeyPair, Date nextUpdate, BigInteger... revokedSerialNumbers) throws Exception {
        X509v2CRLBuilder builder = new X509v2CRLBuilder(new X500Name(caCertificate.getSubjectX500Principal().getName()), hoursFromNow(-1));
        if (nextUpdate != null) {
            builder.setNextUpdate(nextUpdate);
        }

        for (BigInteger serialNumber : revokedSerialNumbers) {
            builder.addCRLEntry(serialNumber, hoursFromNow(-1), 0);
        }

        ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(signingKeyPair.getPrivate());

        return new JcaX509CRLConverter().getCRL(builder.build(signer));
    }

    public static Date hoursFromNow(int hours) {
        return minutesFromNow(hours * 60);
    }

    public static Date minutesFromNow(int minutes) {
        return new Date(System.currentTimeMillis() + (minutes * 60L * 1000));
    }

    private static X509Certificate convert(JcaX509v3CertificateBuilder builder, KeyPair signingKeyPair) throws Exception {
        ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(signingKeyPair.getPrivate());

        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    private static GeneralName uri(String url) {
        return new GeneralName(GeneralName.uniformResourceIdentifier, url);
    }
}
