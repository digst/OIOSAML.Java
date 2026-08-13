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
     * Self signed CA certificate, the issuer of the certificates and CRLs below.
     */
    public static X509Certificate createCaCertificate(KeyPair keyPair, String name) throws Exception {
        X500Name subject = new X500Name("CN=" + name);

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject, BigInteger.ONE, hoursFromNow(-1), hoursFromNow(24), subject, keyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));

        return convert(builder, keyPair);
    }

    /**
     * Certificate naming the given locations as its CRL distribution point and issuer access location, the
     * way the OCES certificates do.
     */
    public static X509Certificate createCertificate(KeyPair keyPair, String name, BigInteger serialNumber, X509Certificate caCertificate, KeyPair caKeyPair, String crlUrl, String caIssuerUrl) throws Exception {
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                caCertificate, serialNumber, hoursFromNow(-1), hoursFromNow(24), new X500Name("CN=" + name), keyPair.getPublic());

        builder.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(new DistributionPoint[] {
                new DistributionPoint(new DistributionPointName(new GeneralNames(uri(crlUrl))), null, null)}));
        builder.addExtension(Extension.authorityInfoAccess, false,
                new AuthorityInformationAccess(AccessDescription.id_ad_caIssuers, uri(caIssuerUrl)));

        return convert(builder, caKeyPair);
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
        return new Date(System.currentTimeMillis() + (hours * 60L * 60 * 1000));
    }

    private static X509Certificate convert(JcaX509v3CertificateBuilder builder, KeyPair signingKeyPair) throws Exception {
        ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(signingKeyPair.getPrivate());

        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    private static GeneralName uri(String url) {
        return new GeneralName(GeneralName.uniformResourceIdentifier, url);
    }
}
