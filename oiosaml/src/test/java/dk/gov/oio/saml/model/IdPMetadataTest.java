package dk.gov.oio.saml.model;

import dk.gov.oio.saml.service.IdpMetadataServiceTest;
import dk.gov.oio.saml.util.ExternalException;
import dk.gov.oio.saml.util.InternalException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class IdPMetadataTest {
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

    private void testSingleLogoutResponseLocation(String idpMetadataFileLocation, String expectedUri) throws ExternalException, InternalException {
        ClassLoader classLoader = IdpMetadataServiceTest.class.getClassLoader();
        String fileLocation = classLoader.getResource(idpMetadataFileLocation).getFile();
        IdPMetadata idpMetadata = new IdPMetadata("http://mockidp.localhost", null, fileLocation);

        String responseLocation = idpMetadata.getLogoutResponseEndpoint();

        Assertions.assertEquals(expectedUri, responseLocation);
    }
}
