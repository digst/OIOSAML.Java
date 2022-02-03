package dk.gov.oio.saml.service;

import dk.gov.oio.saml.config.Configuration;
import dk.gov.oio.saml.session.TestSessionHandlerFactory;
import dk.gov.oio.saml.util.ExternalException;
import dk.gov.oio.saml.util.IdpUtil;
import dk.gov.oio.saml.util.InternalException;
import dk.gov.oio.saml.util.TestConstants;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.opensaml.core.config.InitializationException;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class OIOSAML3ServiceTest {

    @DisplayName("Test that initialization fail if unable to open keystore")
    @Test
    void testInvalidKeystoreConfiguration() throws InternalException, InitializationException {
        Configuration configuration = new Configuration.Builder()
                .setSpEntityID(TestConstants.SP_ENTITY_ID)
                .setBaseUrl(TestConstants.SP_BASE_URL)
                .setServletRoutingPathPrefix(TestConstants.SP_ROUTING_BASE)
                .setServletRoutingPathSuffixError(TestConstants.SP_ROUTING_ERROR)
                .setServletRoutingPathSuffixMetadata(TestConstants.SP_ROUTING_METADATA)
                .setServletRoutingPathSuffixLogout(TestConstants.SP_ROUTING_LOGOUT)
                .setServletRoutingPathSuffixLogoutResponse(TestConstants.SP_ROUTING_LOGOUT_RESPONSE)
                .setServletRoutingPathSuffixAssertion(TestConstants.SP_ROUTING_ASSERTION)
                .setIdpEntityID(TestConstants.IDP_ENTITY_ID)
                .setIdpMetadataUrl(TestConstants.IDP_METADATA_URL)
                .setSessionHandlerFactoryClassName(TestSessionHandlerFactory.class.getName())
                .setKeystoreLocation(TestConstants.SP_KEYSTORE_LOCATION)
                .setKeystorePassword(TestConstants.SP_KEYSTORE_PASSWORD)
                .setKeyAlias("Invalid alias")
                .build();

        Exception initializationException = Assertions.assertThrows(InitializationException.class , () -> {
            OIOSAML3Service.init(configuration);
        });
        Assertions.assertEquals(initializationException.getMessage(), "Unable to initialize OIOSAML 'Malformed configuration in 'oiosaml.servlet.keystore' or keystore file'");

        Exception exception = Assertions.assertThrows(RuntimeException.class , () -> {
            OIOSAML3Service.getCredentialService();
        });
        Assertions.assertEquals(exception.getMessage(), "OIOSAML3 is uninitialized, 'CredentialService' is unavailable");
    }

    @DisplayName("Test that services are initialized with valid configuration")
    @Test
    void testValidConfiguration() throws InternalException, InitializationException {
        Configuration configuration = new Configuration.Builder()
                .setSpEntityID(TestConstants.SP_ENTITY_ID)
                .setBaseUrl(TestConstants.SP_BASE_URL)
                .setServletRoutingPathPrefix(TestConstants.SP_ROUTING_BASE)
                .setServletRoutingPathSuffixError(TestConstants.SP_ROUTING_ERROR)
                .setServletRoutingPathSuffixMetadata(TestConstants.SP_ROUTING_METADATA)
                .setServletRoutingPathSuffixLogout(TestConstants.SP_ROUTING_LOGOUT)
                .setServletRoutingPathSuffixLogoutResponse(TestConstants.SP_ROUTING_LOGOUT_RESPONSE)
                .setServletRoutingPathSuffixAssertion(TestConstants.SP_ROUTING_ASSERTION)
                .setIdpEntityID(TestConstants.IDP_ENTITY_ID)
                .setIdpMetadataUrl(TestConstants.IDP_METADATA_URL)
                .setSessionHandlerFactoryClassName(TestSessionHandlerFactory.class.getName())
                .setKeystoreLocation(TestConstants.SP_KEYSTORE_LOCATION)
                .setKeystorePassword(TestConstants.SP_KEYSTORE_PASSWORD)
                .setKeyAlias(TestConstants.SP_KEYSTORE_ALIAS)
                .build();

        OIOSAML3Service.init(configuration);

        Assertions.assertEquals(configuration, OIOSAML3Service.getConfig());
        Assertions.assertNotNull(OIOSAML3Service.getAuditService());
        Assertions.assertNotNull(OIOSAML3Service.getCredentialService());
        Assertions.assertNotNull(OIOSAML3Service.getSessionCleanerService());
        Assertions.assertNotNull(OIOSAML3Service.getSessionHandlerFactory().getHandler());
    }
}