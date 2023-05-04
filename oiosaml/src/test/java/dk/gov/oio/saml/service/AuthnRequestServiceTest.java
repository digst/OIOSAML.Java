package dk.gov.oio.saml.service;

import dk.gov.oio.saml.config.Configuration;
import dk.gov.oio.saml.extensions.appswitch.*;
import dk.gov.oio.saml.model.NSISLevel;
import dk.gov.oio.saml.session.AuthnRequestWrapper;
import dk.gov.oio.saml.session.TestSessionHandlerFactory;
import dk.gov.oio.saml.util.Constants;
import dk.gov.oio.saml.util.InternalException;
import dk.gov.oio.saml.util.TestConstants;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockserver.client.MockServerClient;
import org.mockserver.junit.jupiter.MockServerExtension;
import org.mockserver.junit.jupiter.MockServerSettings;
import org.mockserver.matchers.Times;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.junit.jupiter.api.Test;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.stream.Stream;

import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

@ExtendWith(MockServerExtension.class)
@MockServerSettings(ports = { 8081 })
public class AuthnRequestServiceTest {

    @BeforeAll
    public static void beforeAll(MockServerClient idp) throws Exception {
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
        
        // make sure IdP responds with useful metadata
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

        XMLObjectProviderRegistrySupport.registerObjectProvider(Platform.DEFAULT_ELEMENT_NAME, new PlatformBuilder(), new PlatformMarshaller(), new PlatformUnmarshaller());
        XMLObjectProviderRegistrySupport.registerObjectProvider(ReturnURL.DEFAULT_ELEMENT_NAME, new ReturnURLBuilder(), new ReturnURLMarshaller(), new ReturnURLUnmarshaller());
        XMLObjectProviderRegistrySupport.registerObjectProvider(AppSwitch.DEFAULT_ELEMENT_NAME, new AppSwitchBuilder(), new AppSwitchMarshaller(), new AppSwitchUnmarshaller());

    }

    @DisplayName("create authn request for appswitch")
    @ParameterizedTest
    @MethodSource("provideTestDataForAppSwitch")
    public void createAuthnRequestWithAppSwitchPlatform(AppSwitchPlatform platform, String expectedReturnUrl) throws Exception {
        Configuration config = OIOSAML3Service.getConfig();
        config.setAppSwitchReturnURLForIOS("https://ios.return.url");
        config.setAppSwitchReturnURLForAndroid("https://android.return.url");

        // Act
        AppSwitch actual = getAuthnRequest(platform);

        // Assert
        Assertions.assertEquals(platform, actual.getPlatform().getValue());
        Assertions.assertEquals(expectedReturnUrl, actual.getReturnURL().getValue());
    }

    @DisplayName("when ReturnURL config is missing, should throw exception")
    @Test
    public void whenReturnURLConfigIsMissingThrowException() {
        Configuration config = OIOSAML3Service.getConfig();
        config.setAppSwitchReturnURLForIOS("https://ios.return.url");
        config.setAppSwitchReturnURLForAndroid(null);

        // Act
        Exception actual = Assertions.assertThrows(Exception.class , () -> getAuthnRequest(AppSwitchPlatform.Android));

        // Assert
        Assertions.assertTrue(actual.getMessage().contains("Missing configuration for '" + Constants.SP_APPSWITCH_RETURNURL_ANDROID));
    }

    private static AppSwitch getAuthnRequest(AppSwitchPlatform appSwitchPlatformEnum) throws InitializationException, InternalException {
        AuthnRequestService service = new AuthnRequestService();
        AuthnRequest authnRequest = service.createAuthnRequest("https://destination.url", false, false, NSISLevel.SUBSTANTIAL, appSwitchPlatformEnum);
        return new AuthnRequestWrapper(authnRequest, NSISLevel.SUBSTANTIAL, "path").getAppSwitch();
    }

    private static Stream<Arguments> provideTestDataForAppSwitch() {
        return Stream.of(
                Arguments.of( AppSwitchPlatform.Android, "https://android.return.url"),
                Arguments.of( AppSwitchPlatform.iOS, "https://ios.return.url")
        );
    }

    private FilterConfig getConfig(boolean isPassive, boolean forceAuthn, String requiredLevel) {
        FilterConfig config = new FilterConfig() {

            @Override
            public Enumeration<String> getInitParameterNames() {
                List<String> keys = new ArrayList<>();
                keys.add(Constants.FORCE_AUTHN);
                keys.add(Constants.IS_PASSIVE);
                if (requiredLevel != null) {
                    keys.add(Constants.REQUIRED_NSIS_LEVEL);
                }

                return Collections.enumeration(keys);
            }

            @Override
            public String getInitParameter(String name) {
                switch (name) {
                    case Constants.IS_PASSIVE:
                        return Boolean.toString(isPassive);
                    case Constants.FORCE_AUTHN:
                        return Boolean.toString(forceAuthn);
                    case Constants.REQUIRED_NSIS_LEVEL:
                        return requiredLevel;

                }

                return null;
            }

            @Override
            public String getFilterName() {
                return "TestConfig";
            }

            @Override
            public ServletContext getServletContext() {
                return null;
            }
        };

        return config;
    }
}
