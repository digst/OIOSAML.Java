package dk.gov.oio.saml.service;

import org.junit.jupiter.api.BeforeEach;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockserver.client.MockServerClient;
import org.mockserver.junit.jupiter.MockServerExtension;
import org.mockserver.junit.jupiter.MockServerSettings;
import org.mockserver.matchers.Times;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;

import dk.gov.oio.saml.config.Configuration;
import dk.gov.oio.saml.util.TestConstants;

@ExtendWith(MockServerExtension.class)
@MockServerSettings(ports = { 8081 })
public class IdpMetadataServiceTest extends BaseServiceTest {
    private MockServerClient idp;

    public IdpMetadataServiceTest(MockServerClient idp) {
        this.idp = idp;
    }

    @BeforeEach
    public void resetMetadata() {
        IdPMetadataService.getInstance().clear(TestConstants.IDP_ENTITY_ID);
    }

    @DisplayName("Test retrieving metadata from file")
    @Test
    public void testGetMetadataFromFile() throws Exception {
        // Metadata file path
        ClassLoader classLoader = IdpMetadataServiceTest.class.getClassLoader();
        String fileLocation = classLoader.getResource("test-metadata.xml").getFile();
        Configuration config = OIOSAML3Service.getConfig();
        config.setIdpMetadataFile(fileLocation);

        // Get metadata
        EntityDescriptor entityDescriptor = IdPMetadataService.getInstance().getIdPMetadata().getEntityDescriptor();
        Assertions.assertNotNull(entityDescriptor);
        Assertions.assertEquals(TestConstants.IDP_ENTITY_ID, entityDescriptor.getEntityID());

        // Cleanup
        config.setIdpMetadataFile(null);
    }

    @DisplayName("Test retrieving metadata")
    @Test
    public void testGetMetadata() throws Exception {
        // Make sure Mock idp is setup to return correct data
        idp
            .when(
                request()
                    .withMethod("GET")
                    .withPath("/saml/metadata"),
                    Times.exactly(1)
            )
            .respond(
                response()
                   .withStatusCode(200)
                   .withBody(TestConstants.IDP_METADATA));
        
        EntityDescriptor entityDescriptor = IdPMetadataService.getInstance().getIdPMetadata().getEntityDescriptor();
        Assertions.assertNotNull(entityDescriptor);
        Assertions.assertEquals(TestConstants.IDP_ENTITY_ID, entityDescriptor.getEntityID());
    }
    
    @DisplayName("Test retrieving incorrect metadata")
    @Test
    public void testGetIncorrectMetadata() throws Exception {
        // Make sure Mock idp is setup to return incorrect data
        idp.when(
                request()
                    .withMethod("GET")
                    .withPath("/saml/metadata"),
                    Times.exactly(1)
            )
            .respond(
                response()
                   .withStatusCode(200)
                   .withBody(TestConstants.BAD_IDP_METADATA));

        // we should get NULL back, if the EntityId does not match
        EntityDescriptor entityDescriptor = IdPMetadataService.getInstance().getIdPMetadata().getEntityDescriptor();
        Assertions.assertNull(entityDescriptor);
    }
}
