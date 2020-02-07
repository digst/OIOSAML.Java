package dk.itst.oiosaml.sp.service;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.HashMap;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.configuration.Configuration;
import org.jmock.Expectations;
import org.junit.Before;
import org.junit.Test;

import dk.itst.oiosaml.sp.model.validation.ValidationException;
import dk.itst.oiosaml.sp.service.session.SingleVMSessionHandlerFactory;
import dk.itst.oiosaml.sp.service.util.Constants;

public class DispatcherServletTest extends AbstractServiceTests {

	private SAMLHandler handler;
	private Configuration configuration;
	private DispatcherServlet servlet;
	private HashMap<String, String> conf;

	@SuppressWarnings("serial")
	@Before
	public void setUp() throws Exception {
		handler = context.mock(SAMLHandler.class);
		servlet = new DispatcherServlet();
		conf = new HashMap<String, String>() {{
			put(Constants.PROP_SESSION_HANDLER_FACTORY, SingleVMSessionHandlerFactory.class.getName());
		}};
		configuration = TestHelper.buildConfiguration(conf);
		servlet.setConfiguration(configuration);
		servlet.setCredential(credential);
		servlet.setIdPMetadata(idpMetadata);
		servlet.setSPMetadata(spMetadata);
		servlet.setSessionHandlerFactory(handlerFactory);
		servlet.setInitialized(true);
	}

	@Test(expected=UnsupportedOperationException.class)
	public void failGetOnNoHandler() throws Exception {
		context.checking(new Expectations() {{
			allowing(req).getRequestURI(); will(returnValue("/void"));
            one(session).getCreationTime(); will(returnValue(0l));
            one(session).getMaxInactiveInterval(); will(returnValue(0));
            one(req).getRemoteAddr(); will(returnValue(""));
            one(session).getAttribute("dk.itst.oiosaml.userassertion"); will(returnValue(null));
		}});
		servlet.doGet(req, res);		
	}
	
	@Test(expected=UnsupportedOperationException.class)
	public void failPostOnNoHandler() throws Exception {
		context.checking(new Expectations() {{
			allowing(req).getRequestURI(); will(returnValue("/void"));
            one(session).getCreationTime(); will(returnValue(0l));
            one(session).getMaxInactiveInterval(); will(returnValue(0));
            one(req).getRemoteAddr(); will(returnValue(""));
            one(session).getAttribute("dk.itst.oiosaml.userassertion"); will(returnValue(null));
		}});
		servlet.doGet(req, res);		
	}

	@Test
	public void samlAssertionConsumerHandler() throws Exception {
		handlePostAndGetForSpecific("SAMLAssertionConsumer");
	}

	@Test
	public void logoutServiceHTTPRedirectHandler() throws Exception {
		handlePostAndGetForSpecific("LogoutServiceHTTPRedirect");
	}

	@Test
	public void logoutHTTPResponseHandler() throws Exception {
		handlePostAndGetForSpecific("LogoutServiceHTTPRedirectResponse");
	}

	@Test
	public void logoutHandler() throws Exception {
		handlePostAndGetForSpecific("Logout");
	}

	@Test
	public void logoutServiceSoapHandler() throws Exception {
		handlePostAndGetForSpecific("LogoutServiceSOAP");
	}
	
	@Test
	public void testDefaultErrorPage() throws Exception {
		final ServletConfig config = context.mock(ServletConfig.class);
		context.checking(new Expectations() {{
			allowing(config).getServletContext(); will(returnValue(null));
			allowing(req).getRequestURI(); will(returnValue("/base/test"));
			one(handler).handleGet(with(any(RequestContext.class))); will(throwException(new ValidationException("test")));
			
			one(res).setContentType("text/html");
			one(res).setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
			one(res).getWriter(); will(returnValue(new PrintWriter(new StringWriter())));

			one(session).getCreationTime(); will(returnValue(0l));
            one(session).getMaxInactiveInterval(); will(returnValue(0));
            one(req).getRemoteAddr(); will(returnValue(""));
            one(session).getAttribute("dk.itst.oiosaml.userassertion"); will(returnValue(null));
			
		}});
		
		servlet.init(config);
		servlet.setHandler(handler, "test");
		servlet.doGet(req, res);
	}
	
	@Test
	public void testCustomErrorPage() throws Exception {
		final ServletConfig config = context.mock(ServletConfig.class);
		final RequestDispatcher dispatcher = context.mock(RequestDispatcher.class);
		context.checking(new Expectations() {{
			allowing(config).getServletContext(); will(returnValue(null));
			allowing(req).getRequestURI(); will(returnValue("/base/test"));
			one(handler).handleGet(with(any(RequestContext.class))); will(throwException(new ValidationException("test")));

			one(req).setAttribute(with(equal(Constants.ATTRIBUTE_ERROR)), with(any(String.class)));
			one(req).setAttribute(with(equal(Constants.ATTRIBUTE_EXCEPTION)), with(any(Expectations.class)));
			one(req).getRequestDispatcher("/error.jsp"); will(returnValue(dispatcher));
			one(dispatcher).forward(req, res);

            one(session).getCreationTime(); will(returnValue(0l));
            one(session).getMaxInactiveInterval(); will(returnValue(0));
            one(req).getRemoteAddr(); will(returnValue(""));
            one(session).getAttribute("dk.itst.oiosaml.userassertion"); will(returnValue(null));
		}});
		
		conf.put(Constants.PROP_ERROR_SERVLET, "/error.jsp");
		servlet.init(config);
		servlet.setHandler(handler, "test");
		servlet.doGet(req, res);
	}

	private void handlePostAndGetForSpecific(final String servletPath) throws Exception {
		servlet.setHandler(handler, servletPath);
		context.checking(new Expectations() {{
			allowing(req).getRequestURI(); will(returnValue("/base/" + servletPath));
			one(handler).handleGet(with(any(RequestContext.class)));
            one(session).getCreationTime(); will(returnValue(0l));
            one(session).getMaxInactiveInterval(); will(returnValue(0));
            one(req).getRemoteAddr(); will(returnValue(""));
            one(session).getAttribute("dk.itst.oiosaml.userassertion"); will(returnValue(null));
		}});
		servlet.doGet(req, res);

		servlet.setHandler(handler, servletPath);
		context.checking(new Expectations() {{
			allowing(req).getRequestURI(); will(returnValue("/base/" + servletPath));
			one(handler).handlePost(with(any(RequestContext.class)));
            one(session).getCreationTime(); will(returnValue(0l));
            one(session).getMaxInactiveInterval(); will(returnValue(0));
            one(req).getRemoteAddr(); will(returnValue(""));
            one(session).getAttribute("dk.itst.oiosaml.userassertion"); will(returnValue(null));
		}});
		servlet.doPost(req, res);
	}
}