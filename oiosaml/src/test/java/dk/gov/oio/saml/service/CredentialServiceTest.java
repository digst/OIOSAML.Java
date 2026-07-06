package dk.gov.oio.saml.service;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.opensaml.core.config.InitializationService;
import org.opensaml.security.x509.BasicX509Credential;

import dk.gov.oio.saml.config.Configuration;
import dk.gov.oio.saml.util.TestConstants;

public class CredentialServiceTest {

    // 'mixedcase-alias.p12' holds a single key entry created with the alias
    // "TestKeyAlias". Java's PKCS12 keystore lowercases aliases on load, so
    // configuring the alias with any other casing used to fail resolving the key
    // and surfaced as a misleading "incorrect keystore password" error (issue #73).
    private static final String MIXED_CASE_KEYSTORE = "mixedcase-alias.p12";
    private static final String ALIAS_IN_DIFFERENT_CASE = "TestKeyAlias";

    @BeforeAll
    public static void initOpenSAML() throws Exception {
        InitializationService.initialize();
    }

    @DisplayName("Keystore alias is resolved case-insensitively (issue #73)")
    @Test
    public void testKeystoreAliasIsCaseInsensitive() throws Exception {
        String keystoreLocation = getClass().getClassLoader().getResource(MIXED_CASE_KEYSTORE).getFile();

        Configuration config = new Configuration.Builder()
                .setSpEntityID(TestConstants.SP_ENTITY_ID)
                .setBaseUrl(TestConstants.SP_BASE_URL)
                .setIdpEntityID(TestConstants.IDP_ENTITY_ID)
                .setIdpMetadataUrl(TestConstants.IDP_METADATA_URL)
                .setKeystoreLocation(keystoreLocation)
                .setKeystorePassword("Test1234")
                .setKeyAlias(ALIAS_IN_DIFFERENT_CASE)
                .build();

        CredentialService credentialService = new CredentialService(config);
        BasicX509Credential credential = credentialService.getPrimaryBasicX509Credential();

        Assertions.assertNotNull(credential, "Key should resolve regardless of the configured alias casing");
    }
}
