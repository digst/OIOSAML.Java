package dk.gov.oio.saml.filter;

import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.mockserver.client.MockServerClient;
import org.mockserver.junit.jupiter.MockServerExtension;
import org.mockserver.junit.jupiter.MockServerSettings;
import org.mockserver.matchers.Times;

import dk.gov.oio.saml.config.Configuration;
import dk.gov.oio.saml.model.NSISLevel;
import dk.gov.oio.saml.service.AssertionServiceTest;
import dk.gov.oio.saml.service.OIOSAML3Service;
import dk.gov.oio.saml.session.AuthnRequestWrapper;
import dk.gov.oio.saml.util.Constants;
import dk.gov.oio.saml.util.TestConstants;

@ExtendWith(MockServerExtension.class)
@MockServerSettings(ports = { 8081 })
public class AuthenticatedFilterTest {

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
	}
	
	@DisplayName("NSIS Substantial login with no existing session")
	@Test
	public void loginSubstantial() throws Exception {
		AuthenticatedFilter filter = new AuthenticatedFilter();
		filter.init(getConfig(false, false, "SUBSTANTIAL"));

		// mock session with state: not logged in at any NSIS level
		HttpSession session = Mockito.mock(HttpSession.class);
		Mockito.when(session.getAttribute(Constants.SESSION_NSIS_LEVEL)).thenReturn(null);
		Mockito.when(session.getAttribute(Constants.SESSION_AUTHENTICATED)).thenReturn(null);

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
		ArgumentCaptor<Object> argument = ArgumentCaptor.forClass(Object.class);
		Mockito.verify(session).setAttribute(Mockito.eq(Constants.SESSION_AUTHN_REQUEST), argument.capture());

		// verify that we have an authnRequest on the session
		Object storedAuthnRequest = argument.getValue();
		Assertions.assertNotNull(storedAuthnRequest);
		Assertions.assertTrue(storedAuthnRequest instanceof AuthnRequestWrapper);		
		AuthnRequestWrapper authnRequest = (AuthnRequestWrapper) storedAuthnRequest;

		// verify that the AuthnRequest is requesting SUBSTANTIAL
		Assertions.assertNotNull(authnRequest.getAuthnContextClassRefValues());
		Assertions.assertTrue(authnRequest.getAuthnContextClassRefValues().size() >= 1);

		boolean foundSubstantialRequest = false;
		for (String authnContextClassRef : authnRequest.getAuthnContextClassRefValues()) {
			if (Constants.LOA_SUBSTANTIAL_URL.equals(authnContextClassRef)) {
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
		Mockito.when(session.getAttribute(Constants.SESSION_NSIS_LEVEL)).thenReturn(NSISLevel.LOW);
		Mockito.when(session.getAttribute(Constants.SESSION_AUTHENTICATED)).thenReturn("true");

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
		ArgumentCaptor<Object> argument = ArgumentCaptor.forClass(Object.class);
		Mockito.verify(session).setAttribute(Mockito.eq(Constants.SESSION_AUTHN_REQUEST), argument.capture());

		// verify that we have an authnRequest on the session
		Object storedAuthnRequest = argument.getValue();
		Assertions.assertNotNull(storedAuthnRequest);
		Assertions.assertTrue(storedAuthnRequest instanceof AuthnRequestWrapper);		
		AuthnRequestWrapper authnRequest = (AuthnRequestWrapper) storedAuthnRequest;

		// verify that the AuthnRequest is requesting SUBSTANTIAL
		Assertions.assertNotNull(authnRequest.getAuthnContextClassRefValues());
		Assertions.assertTrue(authnRequest.getAuthnContextClassRefValues().size() >= 1);

		boolean foundSubstantialRequest = false;
		for (String authnContextClassRef : authnRequest.getAuthnContextClassRefValues()) {
			if (Constants.LOA_SUBSTANTIAL_URL.equals(authnContextClassRef)) {
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
		Mockito.when(session.getAttribute(Constants.SESSION_NSIS_LEVEL)).thenReturn(NSISLevel.SUBSTANTIAL);
		Mockito.when(session.getAttribute(Constants.SESSION_AUTHENTICATED)).thenReturn("true");

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
		Mockito.when(session.getAttribute(Constants.SESSION_NSIS_LEVEL)).thenReturn(null);
		Mockito.when(session.getAttribute(Constants.SESSION_AUTHENTICATED)).thenReturn("true");
		
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
		Mockito.when(session.getAttribute(Constants.SESSION_NSIS_LEVEL)).thenReturn(null);
		Mockito.when(session.getAttribute(Constants.SESSION_AUTHENTICATED)).thenReturn(null);
		
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
		ArgumentCaptor<Object> argument = ArgumentCaptor.forClass(Object.class);
		Mockito.verify(session).setAttribute(Mockito.eq(Constants.SESSION_AUTHN_REQUEST), argument.capture());

		// verify that we have an authnRequest on the session
		Object storedAuthnRequest = argument.getValue();
		Assertions.assertNotNull(storedAuthnRequest);
		Assertions.assertTrue(storedAuthnRequest instanceof AuthnRequestWrapper);		
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
		Mockito.when(session.getAttribute(Constants.SESSION_NSIS_LEVEL)).thenReturn(null);
		Mockito.when(session.getAttribute(Constants.SESSION_AUTHENTICATED)).thenReturn(null);

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
		ArgumentCaptor<Object> argument = ArgumentCaptor.forClass(Object.class);
		Mockito.verify(session).setAttribute(Mockito.eq(Constants.SESSION_AUTHN_REQUEST), argument.capture());

		// verify that we have an authnRequest on the session
		Object storedAuthnRequest = argument.getValue();
		Assertions.assertNotNull(storedAuthnRequest);
		Assertions.assertTrue(storedAuthnRequest instanceof AuthnRequestWrapper);
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
		Mockito.when(session.getAttribute(Constants.SESSION_NSIS_LEVEL)).thenReturn(null);
		Mockito.when(session.getAttribute(Constants.SESSION_AUTHENTICATED)).thenReturn(null);
		
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
		ArgumentCaptor<Object> argument = ArgumentCaptor.forClass(Object.class);
		Mockito.verify(session).setAttribute(Mockito.eq(Constants.SESSION_AUTHN_REQUEST), argument.capture());

		// verify that we have an authnRequest on the session
		Object storedAuthnRequest = argument.getValue();
		Assertions.assertNotNull(storedAuthnRequest);
		Assertions.assertTrue(storedAuthnRequest instanceof AuthnRequestWrapper);		
		AuthnRequestWrapper authnRequest = (AuthnRequestWrapper) storedAuthnRequest;

		// verify that the AuthnRequest is forceAuthn
		Assertions.assertTrue(authnRequest.isPassive());
		Assertions.assertFalse(authnRequest.isForceAuthn());
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
