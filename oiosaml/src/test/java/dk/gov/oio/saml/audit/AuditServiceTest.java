package dk.gov.oio.saml.audit;

import dk.gov.oio.saml.config.Configuration;
import dk.gov.oio.saml.util.InternalException;
import dk.gov.oio.saml.util.TestConstants;
import org.junit.jupiter.api.*;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.opensaml.core.config.InitializationException;
import org.slf4j.Logger;

import static org.junit.jupiter.api.Assertions.*;

class AuditServiceTest {
    private static Logger mockLogger = Mockito.mock(Logger.class);

    public static class TestAuditLogger implements AuditLogger {
        public static Logger log = mockLogger;
        public TestAuditLogger() {  }
        @Override
        public void auditLog(String message) {
            log.info(message);
        }
    }

    public static class InvalidTestAuditLoggerNoInterface {
        public InvalidTestAuditLoggerNoInterface() {  }
        public void auditLog(String message) {  }
    }

    public static class InvalidTestAuditLoggerNoDefault implements AuditLogger {
        public InvalidTestAuditLoggerNoDefault(String value) {  }
        @Override
        public void auditLog(String message) {  }
    }

    private AuditService auditService;
    private Configuration configuration;

    @BeforeEach
    void setupConfiguration() throws InternalException {
        configuration = new Configuration.Builder()
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
                .setKeystoreLocation(TestConstants.SP_KEYSTORE_LOCATION)
                .setKeystorePassword(TestConstants.SP_KEYSTORE_PASSWORD)
                .setKeyAlias(TestConstants.SP_KEYSTORE_ALIAS)
                .build();
    }

    @DisplayName("Test that logged key-value is written to the audit log")
    @Test
    void testAuditLogSuccess() throws InitializationException {
        configuration.setAuditLoggerClassName(TestAuditLogger.class.getName());
        auditService = new AuditService(configuration);

        auditService.auditLog(new AuditService.Builder().withAuthnAttribute("KEY","VALUE"));

        ArgumentCaptor<String> messageCaptor = ArgumentCaptor.forClass(String.class);
        Mockito.verify(mockLogger).info(messageCaptor.capture());

        Assertions.assertTrue(messageCaptor.getValue().contains("\"KEY\":\"VALUE\""));
    }

    @DisplayName("Test that using an audit logger that does not implement auditLogger throws an exception")
    @Test
    void testInvalidAuditLogInterface() {
        configuration.setAuditLoggerClassName(InvalidTestAuditLoggerNoInterface.class.getName());
        Exception exception = assertThrows(InitializationException.class, () -> {
            auditService = new AuditService(configuration);
        });

        String expectedMessage = String.format("Cannot create AuditLogger, '%s' must have default constructor and implement 'dk.gov.oio.saml.audit.AuditLogger'", InvalidTestAuditLoggerNoInterface.class.getName());
        String actualMessage = exception.getMessage();

        assertTrue(actualMessage.contains(expectedMessage));
    }

    @DisplayName("Test that using an audit logger without default constructor throws an exception")
    @Test
    void testInvalidAuditLogConstructor() {
        configuration.setAuditLoggerClassName(InvalidTestAuditLoggerNoDefault.class.getName());
        Exception exception = assertThrows(InitializationException.class, () -> {
            auditService = new AuditService(configuration);
        });

        String expectedMessage = String.format("Cannot create AuditLogger, '%s' must have default constructor", InvalidTestAuditLoggerNoDefault.class.getName());
        String actualMessage = exception.getMessage();

        assertTrue(actualMessage.contains(expectedMessage));
    }
}