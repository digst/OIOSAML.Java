package dk.gov.oio.saml.service;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockserver.client.MockServerClient;
import org.mockserver.junit.jupiter.MockServerExtension;
import org.mockserver.junit.jupiter.MockServerSettings;

import dk.gov.oio.saml.config.Configuration;
import dk.gov.oio.saml.util.TestConstants;

@ExtendWith(MockServerExtension.class)
@MockServerSettings(ports = { 8081 })
public class BaseServiceTest {

    @BeforeAll
    public static void beforeAll(MockServerClient idp) throws Exception {
        ClassLoader classLoader = AssertionServiceTest.class.getClassLoader();
        String keystoreLocation = classLoader.getResource(TestConstants.SP_KEYSTORE_LOCATION).getFile();

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
                .setKeystoreLocation(keystoreLocation)
                .setKeystorePassword(TestConstants.SP_KEYSTORE_PASSWORD)
                .setKeyAlias(TestConstants.SP_KEYSTORE_ALIAS)
                .build();

        configuration.setCRLCheckEnabled(false);
        configuration.setOcspCheckEnabled(false);
        OIOSAML3Service.init(configuration);
    }
}
