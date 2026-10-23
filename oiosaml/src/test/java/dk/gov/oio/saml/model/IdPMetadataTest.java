package dk.gov.oio.saml.model;

import dk.gov.oio.saml.service.BaseServiceTest;
import dk.gov.oio.saml.service.IdpMetadataServiceTest;
import dk.gov.oio.saml.util.ExternalException;
import dk.gov.oio.saml.util.InternalException;
import java.security.cert.X509Certificate;
import java.util.List;

import dk.gov.oio.saml.util.TestConstants;
import org.joda.time.DateTime;
import org.joda.time.DateTimeUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.opensaml.security.credential.UsageType;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class IdPMetadataTest extends BaseServiceTest {
    @DisplayName("Test ResponseLocation is returned when present")
    @Test
    public void testGetLogoutResponseEndpoint_WithResponseLocation() throws ExternalException, InternalException {
        testSingleLogoutResponseLocation("test-metadata.xml", "http://localhost:8081/saml/logout/response");
    }

    @DisplayName("Test Location is returned when ResponseLocation is not present")
    @Test
    public void testGetLogoutResponseEndpoint_WithoutResponseLocation() throws ExternalException, InternalException {
        testSingleLogoutResponseLocation("test-metadata2.xml", "http://localhost:8081/saml/logout");
    }

    @DisplayName("Test Location is returned when ResponseLocation is empty")
    @Test
    public void testGetLogoutResponseEndpoint_WithEmptyResponseLocation() throws ExternalException, InternalException {
        testSingleLogoutResponseLocation("test-metadata3.xml", "http://localhost:8081/saml/logout");
    }

    @AfterEach
    public void resetClock() {
        DateTimeUtils.setCurrentMillisSystem();
    }

    @DisplayName("Test that an IdP signing certificate stops being trusted when it expires while the SP runs")
    @Test
    public void testExpiredSigningCertificateIsNotTrusted() throws Exception {
        IdPMetadata idpMetadata = new IdPMetadata(TestConstants.IDP_ENTITY_ID, TestConstants.writeIdpMetadataFile(TestConstants.IDP_METADATA));
        List<X509Certificate> signing = idpMetadata.getValidX509Certificates(UsageType.SIGNING);
        Assertions.assertFalse(signing.isEmpty());

        DateTimeUtils.setCurrentMillisFixed(new DateTime(signing.get(0).getNotAfter()).plusDays(1).getMillis());

        Assertions.assertTrue(idpMetadata.getValidX509Certificates(UsageType.SIGNING).isEmpty());
    }

    @DisplayName("Test that IdP certificates are checked again after the recheck interval without a metadata change")
    @Test
    public void testCertificatesAreRecheckedPeriodically() throws Exception {
        DateTime start = DateTime.now();
        DateTimeUtils.setCurrentMillisFixed(start.getMillis());
        IdPMetadata idpMetadata = new IdPMetadata(TestConstants.IDP_ENTITY_ID, TestConstants.writeIdpMetadataFile(TestConstants.IDP_METADATA));

        idpMetadata.getValidX509Certificates(UsageType.SIGNING);
        Assertions.assertEquals(start, idpMetadata.getLastCRLCheck());

        DateTimeUtils.setCurrentMillisFixed(start.plusMinutes(30).getMillis());
        idpMetadata.getValidX509Certificates(UsageType.SIGNING);
        Assertions.assertEquals(start, idpMetadata.getLastCRLCheck());

        DateTimeUtils.setCurrentMillisFixed(start.plusMinutes(61).getMillis());
        idpMetadata.getValidX509Certificates(UsageType.SIGNING);
        Assertions.assertEquals(start.plusMinutes(61), idpMetadata.getLastCRLCheck());
    }

    private void testSingleLogoutResponseLocation(String idpMetadataFileLocation, String expectedUri) throws ExternalException, InternalException {
        ClassLoader classLoader = IdpMetadataServiceTest.class.getClassLoader();
        String fileLocation = classLoader.getResource(idpMetadataFileLocation).getFile();
        IdPMetadata idpMetadata = new IdPMetadata("http://mockidp.localhost", fileLocation);

        String responseLocation = idpMetadata.getLogoutResponseEndpoint();

        Assertions.assertEquals(expectedUri, responseLocation);
    }
}
