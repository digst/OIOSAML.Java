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
        String keystoreLocation = classLoader.getResource("sp.pfx").getFile();

		Configuration configuration = new Configuration.Builder()
				.setSpEntityID(TestConstants.SP_ENTITY_ID)
				.setBaseUrl(TestConstants.SP_BASE_URL)
				.setIdpEntityID(TestConstants.IDP_ENTITY_ID)
				.setIdpMetadataUrl(TestConstants.IDP_METADATA_URL)
				.setKeystoreLocation(keystoreLocation)
				.setKeystorePassword("Test1234")
				.setKeyAlias("1")
				.build();

		configuration.setCRLCheckEnabled(false);
		OIOSAML3Service.init(configuration);
	}
}
