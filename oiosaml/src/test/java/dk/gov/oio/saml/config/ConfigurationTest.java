package dk.gov.oio.saml.config;

import dk.gov.oio.saml.util.InternalException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class ConfigurationTest {

    private Configuration minimalConfiguration() throws InternalException {
        // Only the mandatory fields are supplied; every optional value falls back to its default.
        return new Configuration.Builder()
                .setSpEntityID("https://sp.example.com")
                .setBaseUrl("https://sp.example.com")
                .setIdpEntityID("https://idp.example.com")
                .setIdpMetadataUrl("https://idp.example.com/metadata")
                .setKeystoreLocation("keystore.p12")
                .setKeystorePassword("password")
                .setKeyAlias("alias")
                .build();
    }

    @DisplayName("Default audit request attributes map to the matching request value (REF-15, issue #76 sibling)")
    @Test
    void testDefaultAuditRequestAttributes() throws InternalException {
        Configuration configuration = minimalConfiguration();

        // The SessionId audit field must default to the session id and the ServiceProviderUserId
        // audit field to the remote user - these two defaults were previously transposed, so the
        // SESSION_ID column logged the user and the USER column logged the session id.
        Assertions.assertEquals("request:sessionId", configuration.getAuditRequestAttributeSessionId());
        Assertions.assertEquals("request:remoteUser", configuration.getAuditRequestAttributeServiceProviderUserId());
        Assertions.assertEquals("request:remoteAddr", configuration.getAuditRequestAttributeIP());
        Assertions.assertEquals("request:remotePort", configuration.getAuditRequestAttributePort());
    }
}
