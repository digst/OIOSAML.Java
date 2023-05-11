package dk.gov.oio.saml.filter;

import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

import java.util.*;
import java.util.stream.Stream;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import dk.gov.oio.saml.extensions.appswitch.*;
import dk.gov.oio.saml.session.AssertionWrapper;
import dk.gov.oio.saml.session.SessionHandler;
import dk.gov.oio.saml.session.TestSessionHandlerFactory;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.mockserver.client.MockServerClient;
import org.mockserver.junit.jupiter.MockServerExtension;
import org.mockserver.junit.jupiter.MockServerSettings;
import org.mockserver.matchers.Times;

import dk.gov.oio.saml.config.Configuration;
import dk.gov.oio.saml.model.NSISLevel;
import dk.gov.oio.saml.service.OIOSAML3Service;
import dk.gov.oio.saml.session.AuthnRequestWrapper;
import dk.gov.oio.saml.util.Constants;
import dk.gov.oio.saml.util.TestConstants;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;

@ExtendWith(MockServerExtension.class)
@MockServerSettings(ports = { 8081 })
public class AuthenticatedFilterTest {

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
    
    @DisplayName("NSIS Substantial login with no existing session")
    @Test
    public void loginSubstantial() throws Exception {
        AuthenticatedFilter filter = new AuthenticatedFilter();
        filter.init(getConfig(false, false, "SUBSTANTIAL"));

        // mock session with state: not logged in at any NSIS level
        HttpSession session = Mockito.mock(HttpSession.class);

        AssertionWrapper assertionWrapper = Mockito.mock(AssertionWrapper.class);
        Mockito.when(assertionWrapper.getNsisLevel()).thenReturn(null);

        SessionHandler sessionHandler = OIOSAML3Service.getSessionHandlerFactory().getHandler();
        Mockito.when(sessionHandler.getAssertion(session)).thenReturn(assertionWrapper);
        Mockito.when(sessionHandler.isAuthenticated(session)).thenReturn(false);

        // mock request
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getSession()).thenReturn(session);

        // mock response objects to verify behavior later
        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
        FilterChain chain = Mockito.mock(FilterChain.class);

        // invoke method to be tested
        filter.doFilter(request, response, chain);
        
        // verify that the filterChain was not invoked
        Mockito.verify(chain, Mockito.times(0)).doFilter(request, response);

        // capture AUTHN_REQUEST stored on session for inspection
        ArgumentCaptor<AuthnRequestWrapper> argument = ArgumentCaptor.forClass(AuthnRequestWrapper.class);

        Mockito.verify(sessionHandler).storeAuthnRequest(Mockito.eq(session), argument.capture());

        // verify that we have an authnRequest on the session
        Object storedAuthnRequest = argument.getValue();
        Assertions.assertNotNull(storedAuthnRequest);
        AuthnRequestWrapper authnRequest = (AuthnRequestWrapper) storedAuthnRequest;

        // verify that the AuthnRequest is requesting SUBSTANTIAL
        Assertions.assertNotNull(authnRequest.getAuthnContextClassRefValues());
        Assertions.assertTrue(authnRequest.getAuthnContextClassRefValues().size() >= 1);

        boolean foundSubstantialRequest = false;
        for (String authnContextClassRef : authnRequest.getAuthnContextClassRefValues()) {
            if (NSISLevel.SUBSTANTIAL.getUrl().equals(authnContextClassRef)) {
                foundSubstantialRequest = true;
                break;
            }
        }
        Assertions.assertTrue(foundSubstantialRequest);
    }
    
    @DisplayName("NSIS Substantial login with existing session on NSIS Low")
    @Test
    public void loginSubstantialWithExistingLow() throws Exception {
        AuthenticatedFilter filter = new AuthenticatedFilter();
        filter.init(getConfig(false, false, "SUBSTANTIAL"));

        // mock session with state: not logged in at any NSIS level
        HttpSession session = Mockito.mock(HttpSession.class);

        AssertionWrapper assertionWrapper = Mockito.mock(AssertionWrapper.class);
        Mockito.when(assertionWrapper.getNsisLevel()).thenReturn(NSISLevel.LOW);

        SessionHandler sessionHandler = OIOSAML3Service.getSessionHandlerFactory().getHandler();
        Mockito.when(sessionHandler.getAssertion(session)).thenReturn(assertionWrapper);
        Mockito.when(sessionHandler.isAuthenticated(session)).thenReturn(true);

        // mock request
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getSession()).thenReturn(session);

        // mock response objects to verify behavior later
        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
        FilterChain chain = Mockito.mock(FilterChain.class);

        // invoke method to be tested
        filter.doFilter(request, response, chain);
        
        // verify that the filterChain was not invoked
        Mockito.verify(chain, Mockito.times(0)).doFilter(request, response);

        // capture AUTHN_REQUEST stored on session for inspection
        ArgumentCaptor<AuthnRequestWrapper> argument = ArgumentCaptor.forClass(AuthnRequestWrapper.class);

        Mockito.verify(sessionHandler).storeAuthnRequest(Mockito.eq(session), argument.capture());

        // verify that we have an authnRequest on the session
        Object storedAuthnRequest = argument.getValue();
        Assertions.assertNotNull(storedAuthnRequest);
        AuthnRequestWrapper authnRequest = (AuthnRequestWrapper) storedAuthnRequest;

        // verify that the AuthnRequest is requesting SUBSTANTIAL
        Assertions.assertNotNull(authnRequest.getAuthnContextClassRefValues());
        Assertions.assertTrue(authnRequest.getAuthnContextClassRefValues().size() >= 1);

        boolean foundSubstantialRequest = false;
        for (String authnContextClassRef : authnRequest.getAuthnContextClassRefValues()) {
            if (NSISLevel.SUBSTANTIAL.getUrl().equals(authnContextClassRef)) {
                foundSubstantialRequest = true;
                break;
            }
        }
        Assertions.assertTrue(foundSubstantialRequest);
    }
    
    @DisplayName("NSIS Substantial login with existing Substantial session")
    @Test
    public void ssoWithSubstantial() throws Exception {
        AuthenticatedFilter filter = new AuthenticatedFilter();
        filter.init(getConfig(false, false, "SUBSTANTIAL"));

        // mock session with state: logged in at NSIS level SUBSTANTIAL
        HttpSession session = Mockito.mock(HttpSession.class);

        AssertionWrapper assertionWrapper = Mockito.mock(AssertionWrapper.class);
        Mockito.when(assertionWrapper.getNsisLevel()).thenReturn(NSISLevel.SUBSTANTIAL);

        SessionHandler sessionHandler = OIOSAML3Service.getSessionHandlerFactory().getHandler();
        Mockito.when(sessionHandler.getAssertion(session)).thenReturn(assertionWrapper);
        Mockito.when(sessionHandler.isAuthenticated(session)).thenReturn(true);

        // mock request
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getSession()).thenReturn(session);

        // mock response objects to verify behavior later
        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
        FilterChain chain = Mockito.mock(FilterChain.class);

        // invoke method to be tested
        filter.doFilter(request, response, chain);
        
        // verify that the filterChain was invoked (SSO)
        Mockito.verify(chain, Mockito.times(1)).doFilter(request, response);
    }
    
    @DisplayName("Login with existing session (no NSIS)")
    @Test
    public void ssoWithNoNSISLevel() throws Exception {
        AuthenticatedFilter filter = new AuthenticatedFilter();
        filter.init(getConfig(false, false, null));

        // mock session with state: logged in, but no NSIS level set
        HttpSession session = Mockito.mock(HttpSession.class);

        AssertionWrapper assertionWrapper = Mockito.mock(AssertionWrapper.class);
        Mockito.when(assertionWrapper.getNsisLevel()).thenReturn(NSISLevel.NONE);

        SessionHandler sessionHandler = OIOSAML3Service.getSessionHandlerFactory().getHandler();
        Mockito.when(sessionHandler.getAssertion(session)).thenReturn(assertionWrapper);
        Mockito.when(sessionHandler.isAuthenticated(session)).thenReturn(true);
        
        // mock request
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getSession()).thenReturn(session);

        // mock response objects to verify behavior later
        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
        FilterChain chain = Mockito.mock(FilterChain.class);

        // invoke method to be tested
        filter.doFilter(request, response, chain);
        
        // verify that the filterChain was invoked (SSO)
        Mockito.verify(chain, Mockito.times(1)).doFilter(request, response);
    }
    
    @DisplayName("Login with no NSIS level requested")
    @Test
    public void loginWithNoNSISLevel() throws Exception {
        AuthenticatedFilter filter = new AuthenticatedFilter();
        filter.init(getConfig(false, false, null));

        // mock session with state: not logged in at any NSIS level
        HttpSession session = Mockito.mock(HttpSession.class);

        AssertionWrapper assertionWrapper = Mockito.mock(AssertionWrapper.class);
        Mockito.when(assertionWrapper.getNsisLevel()).thenReturn(null);

        SessionHandler sessionHandler = OIOSAML3Service.getSessionHandlerFactory().getHandler();
        Mockito.when(sessionHandler.getAssertion(session)).thenReturn(assertionWrapper);
        Mockito.when(sessionHandler.isAuthenticated(session)).thenReturn(false);
        
        // mock request
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getSession()).thenReturn(session);

        // mock response objects to verify behavior later
        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
        FilterChain chain = Mockito.mock(FilterChain.class);

        // invoke method to be tested
        filter.doFilter(request, response, chain);
        
        // verify that the filterChain was not invoked
        Mockito.verify(chain, Mockito.times(0)).doFilter(request, response);
        
        // capture AUTHN_REQUEST stored on session for inspection
        ArgumentCaptor<AuthnRequestWrapper> argument = ArgumentCaptor.forClass(AuthnRequestWrapper.class);

        Mockito.verify(sessionHandler).storeAuthnRequest(Mockito.eq(session), argument.capture());

        // verify that we have an authnRequest on the session
        Object storedAuthnRequest = argument.getValue();
        Assertions.assertNotNull(storedAuthnRequest);
        AuthnRequestWrapper authnRequest = (AuthnRequestWrapper) storedAuthnRequest;

        // verify that the AuthnRequest is NOT requesting any NSIS level
        Assertions.assertEquals(0, authnRequest.getAuthnContextClassRefValues().size());
    }
    
    @DisplayName("Login with forceAuthn")
    @Test
    public void loginWithForceAuthn() throws Exception {
        AuthenticatedFilter filter = new AuthenticatedFilter();
        filter.init(getConfig(false, true, null));

        // mock session with state: not logged in at any NSIS level
        HttpSession session = Mockito.mock(HttpSession.class);

        AssertionWrapper assertionWrapper = Mockito.mock(AssertionWrapper.class);
        Mockito.when(assertionWrapper.getNsisLevel()).thenReturn(null);

        SessionHandler sessionHandler = OIOSAML3Service.getSessionHandlerFactory().getHandler();
        Mockito.when(sessionHandler.getAssertion(session)).thenReturn(assertionWrapper);
        Mockito.when(sessionHandler.isAuthenticated(session)).thenReturn(false);

        // mock request
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getSession()).thenReturn(session);

        // mock response objects to verify behavior later
        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
        FilterChain chain = Mockito.mock(FilterChain.class);

        // invoke method to be tested
        filter.doFilter(request, response, chain);
        
        // verify that the filterChain was not invoked
        Mockito.verify(chain, Mockito.times(0)).doFilter(request, response);
        
        // capture AUTHN_REQUEST stored on session for inspection
        ArgumentCaptor<AuthnRequestWrapper> argument = ArgumentCaptor.forClass(AuthnRequestWrapper.class);

        Mockito.verify(sessionHandler).storeAuthnRequest(Mockito.eq(session), argument.capture());

        // verify that we have an authnRequest on the session
        Object storedAuthnRequest = argument.getValue();
        Assertions.assertNotNull(storedAuthnRequest);
        AuthnRequestWrapper authnRequest = (AuthnRequestWrapper) storedAuthnRequest;

        // verify that the AuthnRequest is forceAuthn
        Assertions.assertTrue(authnRequest.isForceAuthn());
        Assertions.assertFalse(authnRequest.isPassive());
    }
    
    @DisplayName("Login with isPassive")
    @Test
    public void loginWithIsPassive() throws Exception {
        AuthenticatedFilter filter = new AuthenticatedFilter();
        filter.init(getConfig(true, false, null));

        // mock session with state: not logged in at any NSIS level
        HttpSession session = Mockito.mock(HttpSession.class);

        AssertionWrapper assertionWrapper = Mockito.mock(AssertionWrapper.class);
        Mockito.when(assertionWrapper.getNsisLevel()).thenReturn(null);

        SessionHandler sessionHandler = OIOSAML3Service.getSessionHandlerFactory().getHandler();
        Mockito.when(sessionHandler.getAssertion(session)).thenReturn(assertionWrapper);
        Mockito.when(sessionHandler.isAuthenticated(session)).thenReturn(false);
        
        // mock request
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getSession()).thenReturn(session);

        // mock response objects to verify behavior later
        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
        FilterChain chain = Mockito.mock(FilterChain.class);

        // invoke method to be tested
        filter.doFilter(request, response, chain);
        
        // verify that the filterChain was not invoked
        Mockito.verify(chain, Mockito.times(0)).doFilter(request, response);
        
        // capture AUTHN_REQUEST stored on session for inspection
        ArgumentCaptor<AuthnRequestWrapper> argument = ArgumentCaptor.forClass(AuthnRequestWrapper.class);

        Mockito.verify(sessionHandler).storeAuthnRequest(Mockito.eq(session), argument.capture());

        // verify that we have an authnRequest on the session
        Object storedAuthnRequest = argument.getValue();
        Assertions.assertNotNull(storedAuthnRequest);
        AuthnRequestWrapper authnRequest = (AuthnRequestWrapper) storedAuthnRequest;

        // verify that the AuthnRequest is forceAuthn
        Assertions.assertTrue(authnRequest.isPassive());
        Assertions.assertFalse(authnRequest.isForceAuthn());
    }

    @DisplayName("Setting SESSION_REQUESTED_PATH when authenticating")
    @Test
    public void settingRedirectUrlOnAuthentication() throws Exception {
        AuthenticatedFilter filter = new AuthenticatedFilter();
        filter.init(getConfig(false, false, "SUBSTANTIAL"));

        // mock session with state: not logged in at any NSIS level
        HttpSession session = Mockito.mock(HttpSession.class);

        AssertionWrapper assertionWrapper = Mockito.mock(AssertionWrapper.class);
        Mockito.when(assertionWrapper.getNsisLevel()).thenReturn(null);

        SessionHandler sessionHandler = OIOSAML3Service.getSessionHandlerFactory().getHandler();
        Mockito.when(sessionHandler.getAssertion(session)).thenReturn(assertionWrapper);
        Mockito.when(sessionHandler.isAuthenticated(session)).thenReturn(false);

        // mock request
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getSession()).thenReturn(session);
        Mockito.when(request.getRequestURI()).thenReturn("/some/url");
        Mockito.when(request.getQueryString()).thenReturn("var1=1&var2=2");

        // invoke method to be tested
        filter.doFilter(request, Mockito.mock(HttpServletResponse.class), Mockito.mock(FilterChain.class));

        ArgumentCaptor<AuthnRequestWrapper> authnRequestWrapperArgumentCaptor = ArgumentCaptor.forClass(AuthnRequestWrapper.class);

        // verify that URL is added to the session
        Mockito.verify(sessionHandler, Mockito.times(1)).storeAuthnRequest(Mockito.eq(session), authnRequestWrapperArgumentCaptor.capture());

        Assertions.assertEquals("/some/url?var1=1&var2=2", authnRequestWrapperArgumentCaptor.getValue().getRequestPath());
    }

    @DisplayName("Not setting SESSION_REQUESTED_PATH on current session")
    @Test
    public void settingRedirectUrl() throws Exception {
        AuthenticatedFilter filter = new AuthenticatedFilter();
        filter.init(getConfig(false, false, "SUBSTANTIAL"));

        // mock session with state: logged in at NSIS level SUBSTANTIAL
        HttpSession session = Mockito.mock(HttpSession.class);

        AssertionWrapper assertionWrapper = Mockito.mock(AssertionWrapper.class);
        Mockito.when(assertionWrapper.getNsisLevel()).thenReturn(NSISLevel.SUBSTANTIAL);

        SessionHandler sessionHandler = OIOSAML3Service.getSessionHandlerFactory().getHandler();
        Mockito.when(sessionHandler.getAssertion(session)).thenReturn(assertionWrapper);
        Mockito.when(sessionHandler.isAuthenticated(session)).thenReturn(true);

        // mock request
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getSession()).thenReturn(session);
        Mockito.when(request.getRequestURI()).thenReturn("/some/url");
        Mockito.when(request.getQueryString()).thenReturn("var1=1&var2=2");

        // invoke method to be tested
        filter.doFilter(request, Mockito.mock(HttpServletResponse.class), Mockito.mock(FilterChain.class));

        // verify that authnrequest with URL is not added to the session
        Mockito.verify(sessionHandler, Mockito.never()).storeAuthnRequest(Mockito.eq(session), Mockito.any(AuthnRequestWrapper.class));
    }

    @DisplayName("login with appswitch platform provided")
    @ParameterizedTest
    @MethodSource("provideTestDataForAppSwitch")
    public void whenAppSwitchPlatformIsProvidedInURL_ShouldAddExtension(String platform, String expectedReturnUrl) throws Exception {
        AuthenticatedFilter filter = new AuthenticatedFilter();
        filter.init(getConfig(false, false, "SUBSTANTIAL"));
        Configuration config = OIOSAML3Service.getConfig();
        config.setAppSwitchReturnURLForIOS("https://ios.return.url");
        config.setAppSwitchReturnURLForAndroid("https://android.return.url");

        // mock session with state: not logged in at any NSIS level
        HttpSession session = Mockito.mock(HttpSession.class);

        AssertionWrapper assertionWrapper = Mockito.mock(AssertionWrapper.class);
        Mockito.when(assertionWrapper.getNsisLevel()).thenReturn(null);

        SessionHandler sessionHandler = OIOSAML3Service.getSessionHandlerFactory().getHandler();
        Mockito.when(sessionHandler.getAssertion(session)).thenReturn(assertionWrapper);
        Mockito.when(sessionHandler.isAuthenticated(session)).thenReturn(false);

        // mock request
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getSession()).thenReturn(session);

        HashMap<String, String[]> parameterMap = new HashMap<>();
        String[] parameterValues = new String[1];
        parameterValues[0] = platform;
        parameterMap.put(Constants.APPSWITCH_PLATFORM_QUERY_PARAMETER, parameterValues);
        Mockito.when(request.getParameterMap()).thenReturn(parameterMap);
        Mockito.when(request.getParameter(Constants.APPSWITCH_PLATFORM_QUERY_PARAMETER)).thenReturn(platform);

        // invoke method to be tested
        filter.doFilter(request, Mockito.mock(HttpServletResponse.class), Mockito.mock(FilterChain.class));

        ArgumentCaptor<AuthnRequestWrapper> authnRequestWrapperArgumentCaptor = ArgumentCaptor.forClass(AuthnRequestWrapper.class);
        Mockito.verify(sessionHandler).storeAuthnRequest(Mockito.eq(session), authnRequestWrapperArgumentCaptor.capture());
        AuthnRequestWrapper authnRequest = authnRequestWrapperArgumentCaptor.getValue();

        // Assert
        AppSwitch appSwitch = authnRequest.getAppSwitch();
        Assertions.assertEquals(platform, appSwitch.getPlatform().getValue().toString());
        Assertions.assertEquals(expectedReturnUrl, appSwitch.getReturnURL().getValue());
    }

    @DisplayName("when platform value is unknown should throw exception")
    @ParameterizedTest
    @MethodSource("provideTestDataForAppSwitchErrorScenarios")
    public void whenPlatformIsUnknownShouldThrowException(String platform) throws Exception {
        AuthenticatedFilter filter = new AuthenticatedFilter();
        filter.init(getConfig(false, false, "SUBSTANTIAL"));
        Configuration config = OIOSAML3Service.getConfig();
        config.setAppSwitchReturnURLForIOS("https://ios.return.url");
        config.setAppSwitchReturnURLForAndroid("https://android.return.url");

        // mock session with state: not logged in at any NSIS level
        HttpSession session = Mockito.mock(HttpSession.class);

        AssertionWrapper assertionWrapper = Mockito.mock(AssertionWrapper.class);
        Mockito.when(assertionWrapper.getNsisLevel()).thenReturn(null);

        SessionHandler sessionHandler = OIOSAML3Service.getSessionHandlerFactory().getHandler();
        Mockito.when(sessionHandler.getAssertion(session)).thenReturn(assertionWrapper);
        Mockito.when(sessionHandler.isAuthenticated(session)).thenReturn(false);

        // mock request
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getSession()).thenReturn(session);
        HashMap<String, String[]> parameterMap = new HashMap<>();
        String[] parameterValues = new String[1];
        parameterValues[0] = platform;
        parameterMap.put(Constants.APPSWITCH_PLATFORM_QUERY_PARAMETER, parameterValues);
        Mockito.when(request.getParameterMap()).thenReturn(parameterMap);
        Mockito.when(request.getParameter(Constants.APPSWITCH_PLATFORM_QUERY_PARAMETER)).thenReturn(platform);

        // Assert && Assert
        ServletException thrownException = Assertions.assertThrows(ServletException.class , () -> {
            filter.doFilter(request, Mockito.mock(HttpServletResponse.class), Mockito.mock(FilterChain.class));
        });

        Assertions.assertTrue(thrownException.getMessage().contains("Could not parse platform from appSwitchPlatform query parameter: '" + platform));
    }

    private static Stream<Arguments> provideTestDataForAppSwitch() {
        return Stream.of(
                Arguments.of( "Android", "https://android.return.url"),
                Arguments.of( "iOS", "https://ios.return.url")
        );
    }

    private static Stream<Arguments> provideTestDataForAppSwitchErrorScenarios() {
        return Stream.of(
                Arguments.of( "FireFoxOS"),
                Arguments.of( " "),
                Arguments.of( new Object[1])
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
