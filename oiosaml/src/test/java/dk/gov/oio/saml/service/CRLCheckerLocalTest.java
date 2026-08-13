package dk.gov.oio.saml.service;

import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockserver.client.MockServerClient;

import dk.gov.oio.saml.util.TestPkiUtil;

/**
 * Revocation checking against a locally served CA, so the CRL can be tampered with. The tests against the
 * live NemLog-in test CA are in {@link CRLCheckerTest}.
 */
public class CRLCheckerLocalTest extends BaseServiceTest {
    private static final String CRL_PATH = "/test-ca/crl";
    private static final String CA_ISSUER_PATH = "/test-ca/cacert";
    private static final BigInteger SERIAL_NUMBER = BigInteger.valueOf(4711);

    private KeyPair caKeyPair;
    private X509Certificate caCertificate;
    private X509Certificate certificate;

    @BeforeEach
    public void beforeEach(MockServerClient mockServer) throws Exception {
        OIOSAML3Service.getConfig().setCRLCheckEnabled(true);
        OIOSAML3Service.getConfig().setOcspCheckEnabled(false);

        caKeyPair = TestPkiUtil.generateKeyPair();
        caCertificate = TestPkiUtil.createCaCertificate(caKeyPair, "OIOSAML test CA");
        certificate = TestPkiUtil.createCertificate(TestPkiUtil.generateKeyPair(), "OIOSAML test certificate", SERIAL_NUMBER,
                caCertificate, caKeyPair, url(CRL_PATH), url(CA_ISSUER_PATH));

        mockServer.reset();
        mockServer.when(request().withPath(CA_ISSUER_PATH)).respond(response().withBody(caCertificate.getEncoded()));
    }

    @DisplayName("Test that a certificate absent from a valid CRL is accepted")
    @Test
    public void testAcceptCertificateAbsentFromCrl(MockServerClient mockServer) throws Exception {
        serveCrl(mockServer, TestPkiUtil.createCrl(caCertificate, caKeyPair, TestPkiUtil.hoursFromNow(24)));

        Assertions.assertEquals(1, checkCertificate().size());
    }

    @DisplayName("Test that a certificate listed in a valid CRL is rejected")
    @Test
    public void testRejectCertificateListedInCrl(MockServerClient mockServer) throws Exception {
        serveCrl(mockServer, TestPkiUtil.createCrl(caCertificate, caKeyPair, TestPkiUtil.hoursFromNow(24), SERIAL_NUMBER));

        Assertions.assertEquals(0, checkCertificate().size());
    }

    @DisplayName("Test that a CRL signed by another key is not trusted")
    @Test
    public void testRejectCrlSignedByAnotherKey(MockServerClient mockServer) throws Exception {
        // Same content as the accepted list above, only the signing key differs
        serveCrl(mockServer, TestPkiUtil.createCrl(caCertificate, TestPkiUtil.generateKeyPair(), TestPkiUtil.hoursFromNow(24)));

        Assertions.assertEquals(0, checkCertificate().size());
    }

    @DisplayName("Test that a CRL that is no longer current is not trusted")
    @Test
    public void testRejectStaleCrl(MockServerClient mockServer) throws Exception {
        serveCrl(mockServer, TestPkiUtil.createCrl(caCertificate, caKeyPair, TestPkiUtil.hoursFromNow(-12)));

        Assertions.assertEquals(0, checkCertificate().size());
    }

    @DisplayName("Test that a CRL without a nextUpdate is not trusted")
    @Test
    public void testRejectCrlWithoutNextUpdate(MockServerClient mockServer) throws Exception {
        serveCrl(mockServer, TestPkiUtil.createCrl(caCertificate, caKeyPair, (Date) null));

        Assertions.assertEquals(0, checkCertificate().size());
    }

    @DisplayName("Test that a certificate not issued by the CA at its issuer location is rejected")
    @Test
    public void testRejectCertificateNotIssuedByServedCa(MockServerClient mockServer) throws Exception {
        // The CA certificate served at the issuer location belongs to a different CA
        KeyPair otherCaKeyPair = TestPkiUtil.generateKeyPair();
        X509Certificate otherCaCertificate = TestPkiUtil.createCaCertificate(otherCaKeyPair, "OIOSAML test CA");

        mockServer.reset();
        mockServer.when(request().withPath(CA_ISSUER_PATH)).respond(response().withBody(otherCaCertificate.getEncoded()));
        serveCrl(mockServer, TestPkiUtil.createCrl(otherCaCertificate, otherCaKeyPair, TestPkiUtil.hoursFromNow(24)));

        Assertions.assertEquals(0, checkCertificate().size());
    }

    private void serveCrl(MockServerClient mockServer, X509CRL crl) throws Exception {
        mockServer.when(request().withPath(CRL_PATH)).respond(response().withBody(crl.getEncoded()));
    }

    private Set<X509Certificate> checkCertificate() throws Exception {
        List<X509Certificate> certificates = Collections.singletonList(certificate);

        return CRLChecker.checkCertificates(certificates, null);
    }

    private static String url(String path) {
        return "http://localhost:8081" + path;
    }
}
