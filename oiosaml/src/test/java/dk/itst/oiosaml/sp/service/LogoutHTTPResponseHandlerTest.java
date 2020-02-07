package dk.itst.oiosaml.sp.service;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.HashMap;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.configuration.Configuration;
import org.jmock.Expectations;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.xml.util.XMLHelper;

import dk.itst.oiosaml.sp.model.OIOLogoutRequest;
import dk.itst.oiosaml.sp.model.OIOLogoutResponse;
import dk.itst.oiosaml.sp.service.util.Constants;
import dk.itst.oiosaml.sp.service.util.Utils;

public class LogoutHTTPResponseHandlerTest extends AbstractServiceTests {
	
	private LogoutHTTPResponseHandler lh;
	private Configuration configuration;
	private RequestContext ctx;

	@SuppressWarnings("serial")
	@Before
	public void setUp() throws NoSuchAlgorithmException, NoSuchProviderException {
		lh = new LogoutHTTPResponseHandler();

		configuration = TestHelper.buildConfiguration(new HashMap<String, String>() {{
			put(Constants.PROP_HOME, "url");
		}});
		ctx = new RequestContext(req, res, idpMetadata, spMetadata, credential, configuration, handler, bindingHandlerFactory);
	}

	@Test
	public void testReceiveResponseNotLoggedIn() throws Exception {
		OIOLogoutRequest lr = OIOLogoutRequest.buildLogoutRequest(session, "http://slo", idpEntityId, handler);
		handler.registerRequest(lr.getID(), idpEntityId);

		OIOLogoutResponse resp = OIOLogoutResponse.fromRequest(lr, StatusCode.SUCCESS_URI, "consent", idpEntityId, spMetadata.getSingleLogoutServiceHTTPRedirectResponseLocation());
		String responseUrl = resp.getRedirectURL(credential, "relayState");
		setExpectations(req, responseUrl, spMetadata.getSingleLogoutServiceHTTPRedirectResponseLocation());
		
		context.checking(new Expectations() {{
			one(res).sendRedirect("url");
			one(session).removeAttribute(Constants.SESSION_USER_ASSERTION);
		}});
		lh.handleGet(ctx);
	} 
	
	@Test(expected=IllegalArgumentException.class)
	public void testReceiveResponseLoggedIn() throws Exception{
		
		OIOLogoutRequest lr = OIOLogoutRequest.buildLogoutRequest(session, "http://slo", idpEntityId, handler);
		handler.registerRequest(lr.getID(), idpMetadata.getFirstMetadata().getEntityID());
		
		OIOLogoutResponse resp = OIOLogoutResponse.fromRequest(lr, StatusCode.SUCCESS_URI, "consent", idpEntityId, spMetadata.getSingleLogoutServiceHTTPRedirectResponseLocation());
		
		String responseUrl = resp.getRedirectURL(credential, "relayState");
		setExpectations(req, responseUrl, spMetadata.getSingleLogoutServiceHTTPRedirectResponseLocation());
		
		context.checking(new Expectations() {{
			one(res).sendRedirect("url");
			one(session).removeAttribute(Constants.SESSION_USER_ASSERTION);
		}});
		lh.handleGet(ctx);
		
		System.out.println(XMLHelper.nodeToString(TestHelper.parseBase64Encoded("nVLLbsIwELzzFZHvedh5OLFCpKocikQlBIhDL5VxNjQi2MjroH5%2BDYiiXjjUh%2FWuNTO7HrtemL0Z3QrwZDRCMAN0vZauN3pKvpw7oYhjRtOIpTyiBY1KKsosS2PTG5THIb6Gm8ga7LlX8LbZLFfQ9haUI8F8NiWfVZd0u06xihcFbynvZJvzIs9VsWNclhkrM%2Bqh%2Bj7GxngSKxjjvJKhKtM0zHaKhruMy7DNvRz41aXgSYgjzDU6qd2UsCQpw6QKab6hTLBUZNUHCbZg8XohFiUk%2BD4OGqdktFoYiT0KLY%2BAwimxfnlfCI8RJ2ucUWYgTa2RimsPeyMKf%2FCcLBHBXgwkzd3Ai0nRYPa9PlmIzr09RO2hjh%2FaTb120o14319NC8FWDiM874VXtFiPSgEi%2BSd9Kf28cri9IombOn7I%2FBY%2B%2BftXmsnkBw%3D%3D", true).getDocumentElement()));
		handler.removeEntityIdForRequest(lr.getID());
		
	}
	
	// TODO: test is broken, there is an extra "/saml" in one of the URL's when comparing, not sure why
//	@Test
	public void testReceiveResponseCluster() throws Exception {
		OIOLogoutRequest lr = OIOLogoutRequest.buildLogoutRequest(session, "http://cluster", idpEntityId, handler);
		handler.registerRequest(lr.getID(), idpMetadata.getFirstMetadata().getEntityID());
		
		OIOLogoutResponse resp = OIOLogoutResponse.fromRequest(lr, StatusCode.SUCCESS_URI, "consent", idpEntityId, spMetadata.getSingleLogoutServiceHTTPRedirectResponseLocation());
		
		String responseUrl = resp.getRedirectURL(credential, "relayState");
		setExpectations(req, responseUrl, "https://cluster:80/saml/LogoutServiceHTTPRedirectResponse");
		
		context.checking(new Expectations() {{
			one(res).sendRedirect("url");
			one(session).removeAttribute(Constants.SESSION_USER_ASSERTION);
		}});
		
		String url = spMetadata.getDefaultAssertionConsumerService().getLocation();
		String hostname = url.substring(0, url.indexOf('/', 8));
		ctx = new RequestContext(new SAMLHttpServletRequest(req, hostname, null), res, idpMetadata, spMetadata, credential, configuration, handler, bindingHandlerFactory);

		lh.handleGet(ctx);
		
	}

	private void setExpectations(final HttpServletRequest req,
			final String responseUrl, final String requestUrl) throws UnsupportedEncodingException {
		context.checking(new Expectations() {{
			allowing(req).getRequestURI(); will(returnValue("/"));
			allowing(req).getQueryString(); will(returnValue(responseUrl.substring(responseUrl.indexOf('?') + 1)));
			allowing(req).getParameter("SAMLResponse"); will(returnValue(URLDecoder.decode(Utils.getParameter("SAMLResponse", responseUrl), "UTF-8")));
			allowing(req).getParameter("SAMLRequest"); will(returnValue(null));
			allowing(req).getParameter("RelayState"); will(returnValue(URLDecoder.decode(Utils.getParameter("RelayState", responseUrl), "UTF-8")));
			allowing(req).getParameter("SigAlg"); will(returnValue(URLDecoder.decode(Utils.getParameter("SigAlg", responseUrl), "UTF-8")));
			allowing(req).getParameter("Signature"); will(returnValue(URLDecoder.decode(Utils.getParameter("Signature", responseUrl), "UTF-8")));
			allowing(req).getMethod(); will(returnValue("GET"));
			allowing(req).getRequestURL(); will(returnValue(new StringBuffer(requestUrl)));
		}});
	}
	
}
