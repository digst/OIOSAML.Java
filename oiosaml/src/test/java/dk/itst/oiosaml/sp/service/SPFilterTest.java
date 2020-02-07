package dk.itst.oiosaml.sp.service;

import static dk.itst.oiosaml.sp.service.TestHelper.getCredential;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.configuration.Configuration;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.jmock.Expectations;
import org.junit.Before;
import org.junit.Test;

import dk.itst.oiosaml.configuration.SAMLConfigurationFactory;
import dk.itst.oiosaml.sp.OIOPrincipal;
import dk.itst.oiosaml.sp.UserAssertionHolder;
import dk.itst.oiosaml.sp.UserAssertionImpl;
import dk.itst.oiosaml.sp.develmode.DevelMode;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.service.session.SingleVMSessionHandlerFactory;
import dk.itst.oiosaml.sp.service.util.Constants;

public class SPFilterTest extends AbstractServiceTests {

	private static final class BaseMatcherExtension extends BaseMatcher<ServletRequest> {
		public boolean matches(Object item) {
			HttpServletRequest req = (HttpServletRequest)item;
			String remoteUser = (req).getRemoteUser();
			if (!remoteUser.equals("joetest")) {
				return false;
			}
			assertNotNull(req.getUserPrincipal());
			assertTrue(req.getUserPrincipal() instanceof OIOPrincipal);
			OIOPrincipal p = (OIOPrincipal) req.getUserPrincipal();
			assertEquals("joetest", p.getName());
			assertNotNull(p.getAssertion());
			
			// test url rewriting in getRequestURL
			String url = req.getRequestURL().toString();
			assertEquals("http://trifork.com:8888/saml/service", url);
			
			return true;
		}

		public void describeTo(Description description) {
		}
	}

	private FilterChain chain;
	private SPFilter filter;
	private Map<String, String> conf = new HashMap<String, String>();

	@Before
	public void setUp() throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		credential = getCredential();
		chain = context.mock(FilterChain.class);
		context.checking(new Expectations() {{
			allowing(req).getRequestURI(); will(returnValue("http://test"));
			allowing(req).getPathInfo(); will(returnValue("/test"));
			allowing(req).getRequestURL(); will(returnValue(new StringBuffer("http://test/saml/service")));
			allowing(req).getQueryString();
			allowing(req).getServletPath(); will(returnValue("/servlet"));
			allowing(req).getMethod(); will(returnValue("GET"));
			allowing(session).getMaxInactiveInterval(); will(returnValue(30));
			allowing(req).getRemoteAddr(); will(returnValue("127.0.0.1"));
		}});
		
		filter = new SPFilter();
		conf.put(Constants.PROP_ASSURANCE_LEVEL, "1");
		conf.put(Constants.PROP_SESSION_HANDLER_FACTORY, SingleVMSessionHandlerFactory.class.getName());
		conf.put(Constants.PROP_PROTOCOL + ".saml20", "/login");
		//CompositeConfiguration cc =new CompositeConfiguration();
		
		filter.setConfiguration(TestHelper.buildConfiguration(conf));
		
		filter.setSessionHandlerFactory(handlerFactory);
		filter.setFilterInitialized(true);
		filter.setHostname("http://trifork.com:8888");
	}
	
	@Test
	public void failOnNotConfigured() throws ServletException, IOException {
		final File dir = new File(File.createTempFile("test", "test").getAbsolutePath() + "dir");
		dir.mkdir();
		
		SPFilter filter = new SPFilter();
        SAMLConfigurationFactory.getConfiguration().setInitConfiguration(new HashMap<String, String>()); // Configuration has been set in the "before test" method. We need to unset the configuration in order for this test to pass.
		final FilterConfig config = context.mock(FilterConfig.class);
		context.checking(new Expectations(){{
			one(session).getAttribute(Constants.SESSION_USER_ASSERTION); will(returnValue(null));
            one(session).getCreationTime(); will(returnValue(0l));
		}});
		filter.init(config);
		
		final RequestDispatcher dispatcher = context.mock(RequestDispatcher.class);
		
		context.checking(new Expectations(){{
			one(req).getRequestDispatcher("/saml/configure"); will(returnValue(dispatcher));
			one(dispatcher).forward(req, res);
		}});

		filter.doFilter(req, res, chain);
		
		dir.delete();
	}

	@Test
	public void redirectWhenNotLoggedIn() throws Exception {
		
		final RequestDispatcher dispatcher = context.mock(RequestDispatcher.class);
		UserAssertionHolder.set(new UserAssertionImpl(new OIOAssertion(assertion)));		
		context.assertIsSatisfied();
		context.checking(new Expectations() {{
            allowing(req).getParameterMap();
			one(session).removeAttribute(Constants.SESSION_USER_ASSERTION);
			one(req).getRequestDispatcher("/saml/login"); will(returnValue(dispatcher));
			one(dispatcher).forward(with(any(HttpServletRequest.class)), with(equal(res)));
			one(session).getAttribute(Constants.SESSION_USER_ASSERTION); will(returnValue(null));
            one(session).getCreationTime(); will(returnValue(0l));
		}});
		
		filter.doFilter(req, res, chain);
		assertNull(UserAssertionHolder.get());
	}
	
	@Test
	public void doFilterWhenAuthenticated() throws Exception {
		UserAssertionHolder.set(null);
		
		setHandler();
		final BaseMatcher<ServletRequest> baseMatcher = new BaseMatcherExtension();
		context.checking(new Expectations() {{
            allowing(req).getParameterMap();
			one(session).getAttribute(Constants.SESSION_USER_ASSERTION); will(returnValue(new UserAssertionImpl(new OIOAssertion(assertion))));
			one(session).getAttribute(Constants.SESSION_USER_ASSERTION); will(returnValue(new UserAssertionImpl(new OIOAssertion(assertion))));
			one(session).getAttribute(Constants.SESSION_USER_ASSERTION); will(returnValue(new UserAssertionImpl(new OIOAssertion(assertion))));
			one(chain).doFilter(with(baseMatcher) , with(any(HttpServletResponse.class)));
            one(session).getCreationTime(); will(returnValue(0l));
		}});
		filter.doFilter(req, res, new FilterChain() {
			public void doFilter(ServletRequest arg0, ServletResponse arg1) throws IOException, ServletException {
				assertNotNull(UserAssertionHolder.get());
				chain.doFilter(arg0, arg1);
			}
		});
		
		assertNull(UserAssertionHolder.get());
	}
	
	@Test
	public void failWhenAssuranceLevelIsTooLow() throws Exception {
		conf.put(Constants.PROP_ASSURANCE_LEVEL, "4");
		setHandler();
		context.checking(new Expectations() {{
            one(req).getParameterMap();
			one(session).getAttribute(Constants.SESSION_USER_ASSERTION); will(returnValue(new UserAssertionImpl(new OIOAssertion(assertion))));
			one(session).getAttribute(Constants.SESSION_USER_ASSERTION); will(returnValue(new UserAssertionImpl(new OIOAssertion(assertion))));
			one(session).removeAttribute(Constants.SESSION_USER_ASSERTION);
            one(session).getCreationTime(); will(returnValue(0l));
		}});
		try {
			filter.doFilter(req, res, chain);
			fail("assurance level should be too low");
		} catch (RuntimeException e) {}
	}
	
	@Test
	public void doFilterWhenRequestAgainstSAMLServlet() throws Exception {
		conf.put(Constants.PROP_SAML_SERVLET, "/servlet");
		context.checking(new Expectations() {{
			one(chain).doFilter(with(any(HttpServletRequest.class)), with(equal(res)));
			one(session).getAttribute(Constants.SESSION_USER_ASSERTION); will(returnValue(null));
            one(session).getCreationTime(); will(returnValue(0l));
		}});
		
		filter.doFilter(req, res, chain);
	}
	
	@Test
	public void testDevelModeDelegatesToDevelModeObject() throws Exception {
		conf.put(Constants.PROP_DEVEL_MODE, "true");
		filter.setConfiguration(TestHelper.buildConfiguration(conf));
		final DevelMode develMode = context.mock(DevelMode.class);
		filter.setDevelMode(develMode);
		
		context.checking(new Expectations() {{
			one(session).getAttribute(Constants.SESSION_USER_ASSERTION); will(returnValue(null));
			one(develMode).doFilter(with(equal(req)), with(equal(res)), with(equal(chain)), with(any(Configuration.class)));
            one(session).getCreationTime(); will(returnValue(0l));
            
		}});
		
		filter.doFilter(req, res, chain);
	}
}
