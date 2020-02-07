package dk.itst.oiosaml.sp.service;

import static dk.itst.oiosaml.sp.service.TestHelper.parseBase64Encoded;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.HashMap;

import javax.xml.parsers.ParserConfigurationException;

import org.jmock.Expectations;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.Configuration;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.xml.io.UnmarshallingException;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import dk.itst.oiosaml.error.WrappedException;
import dk.itst.oiosaml.sp.model.OIOLogoutRequest;
import dk.itst.oiosaml.sp.service.LogoutServiceHTTPRedirectHandler;
import dk.itst.oiosaml.sp.service.util.Constants;
import dk.itst.oiosaml.sp.service.util.Utils;

public class LogoutServiceHTTPRedirectHandlerTest extends AbstractServiceTests {
	
	private LogoutServiceHTTPRedirectHandler logoutServiceHttpRedirectHandler;
	private StringValueHolder urlExtractor = new StringValueHolder();
	private RequestContext ctx;

	@Before
	public void setUp() throws NoSuchAlgorithmException, NoSuchProviderException {
		logoutServiceHttpRedirectHandler = new LogoutServiceHTTPRedirectHandler();
		ctx = new RequestContext(req, res, idpMetadata, spMetadata, credential, TestHelper.buildConfiguration(new HashMap<String, String>()), handler, bindingHandlerFactory);
	}

	@Test
	public void failOnIllegalBodyContent() throws Exception {
		context.checking(new Expectations() {{
			allowing(req).getParameter("SAMLRequest"); will(returnValue("illegal"));
			allowing(req).getParameter("RelayState"); will(returnValue(null));
			allowing(req).getParameter("SigAlg"); will(returnValue("alg"));
			allowing(req).getParameter("Signature"); will(returnValue("sig"));
			allowing(req).getMethod(); will(returnValue("GET"));
			allowing(req).getRequestURL(); will(returnValue(new StringBuffer("http://slo")));
			allowing(req).getQueryString(); will(returnValue("url"));
			
		}});
		try {
			logoutServiceHttpRedirectHandler.handleGet(ctx);
			fail("samlrequest is not well-formed");
		} catch (WrappedException e) {
			assertTrue(e.getCause() instanceof MessageDecodingException);
		}
	} 
	
	@Test
	public void testRedirect() throws Exception {
		setHandler();
		assertTrue(handler.isLoggedIn(session.getId()));
		OIOLogoutRequest lr = OIOLogoutRequest.buildLogoutRequest(session, spMetadata.getSingleLogoutServiceHTTPRedirectLocation(), idpEntityId, handler);
		final String requestURL = lr.getRedirectRequestURL(credential);
		
		context.checking(new Expectations() {{
			allowing(req).getParameter("SAMLRequest"); will(returnValue(URLDecoder.decode(Utils.getParameter("SAMLRequest", requestURL), "UTF-8")));
			allowing(req).getParameter("RelayState"); will(returnValue(null));
			allowing(req).getParameter("SigAlg"); will(returnValue(URLDecoder.decode(Utils.getParameter("SigAlg", requestURL), "UTF-8")));
			allowing(req).getParameter("Signature"); will(returnValue(URLDecoder.decode(Utils.getParameter("Signature", requestURL), "UTF-8")));
			allowing(req).getMethod(); will(returnValue("GET"));
			allowing(req).getRequestURL(); will(returnValue(new StringBuffer(spMetadata.getSingleLogoutServiceHTTPRedirectLocation())));
			allowing(req).getQueryString(); will(returnValue(requestURL.substring(requestURL.indexOf('?') + 1)));
			one(res).sendRedirect(with(urlExtractor));
			one(session).removeAttribute(Constants.SESSION_USER_ASSERTION);
		}});
		
		logoutServiceHttpRedirectHandler.handleGet(ctx);
		
		assertFalse(handler.isLoggedIn(session.getId()));
		LogoutResponse lresp = parseResponse();
		assertEquals(StatusCode.SUCCESS_URI, lresp.getStatus().getStatusCode().getValue());
	}

	@Test
	public void failWhenInvalidSignature() throws Exception {
		OIOLogoutRequest lr = OIOLogoutRequest.buildLogoutRequest(session, spMetadata.getSingleLogoutServiceHTTPRedirectLocation(), idpEntityId, handler);
		final String requestURL = lr.getRedirectRequestURL(credential);
		
		context.checking(new Expectations() {{
			allowing(req).getParameter("SAMLRequest"); will(returnValue(URLDecoder.decode(Utils.getParameter("SAMLRequest", requestURL), "UTF-8")));
			allowing(req).getParameter("RelayState"); will(returnValue(null));
			allowing(req).getParameter("SigAlg"); will(returnValue(URLDecoder.decode(Utils.getParameter("SigAlg", requestURL), "UTF-8")));
			
			// destroy the signature value to make it fail
			allowing(req).getParameter("Signature"); will(returnValue("test" + URLDecoder.decode(Utils.getParameter("Signature", requestURL), "UTF-8")));
			allowing(req).getMethod(); will(returnValue("GET"));
			allowing(req).getRequestURL(); will(returnValue(new StringBuffer(spMetadata.getSingleLogoutServiceHTTPRedirectLocation())));
			allowing(req).getQueryString(); will(returnValue(requestURL.substring(requestURL.indexOf('?') + 1)));
			one(res).sendRedirect(with(urlExtractor));
		}});
		
		logoutServiceHttpRedirectHandler.handleGet(ctx);
		LogoutResponse lresp = parseResponse();
		assertEquals(StatusCode.AUTHN_FAILED_URI, lresp.getStatus().getStatusCode().getValue());
	}
	
	
	@Test(expected=IllegalArgumentException.class)
	public void testFailWhenIssuerIsWrong() throws Exception {
		OIOLogoutRequest lr = OIOLogoutRequest.buildLogoutRequest(session, spMetadata.getSingleLogoutServiceHTTPRedirectLocation(), "entityID", handler);
		final String requestURL = lr.getRedirectRequestURL(credential);
		
		context.checking(new Expectations() {{
			allowing(req).getParameter("SAMLRequest"); will(returnValue(URLDecoder.decode(Utils.getParameter("SAMLRequest", requestURL), "UTF-8")));
			allowing(req).getParameter("RelayState"); will(returnValue(null));
			allowing(req).getParameter("SigAlg"); will(returnValue(URLDecoder.decode(Utils.getParameter("SigAlg", requestURL), "UTF-8")));
			allowing(req).getParameter("Signature"); will(returnValue(URLDecoder.decode(Utils.getParameter("Signature", requestURL), "UTF-8")));
			allowing(req).getMethod(); will(returnValue("GET"));
			allowing(req).getRequestURL(); will(returnValue(new StringBuffer(spMetadata.getSingleLogoutServiceHTTPRedirectLocation())));
			allowing(req).getQueryString(); will(returnValue(requestURL.substring(requestURL.indexOf('?') + 1)));
		}});
		
		logoutServiceHttpRedirectHandler.handleGet(ctx);
	}
	
	@Test(expected=RuntimeException.class)
	public void failWhenNoIssuer() throws Exception {
		OIOLogoutRequest lr = OIOLogoutRequest.buildLogoutRequest(session, spMetadata.getSingleLogoutServiceHTTPRedirectLocation(), null, handler);
		final String requestURL = lr.getRedirectRequestURL(credential);
		
		context.checking(new Expectations() {{
			allowing(req).getParameter("SAMLRequest"); will(returnValue(URLDecoder.decode(Utils.getParameter("SAMLRequest", requestURL), "UTF-8")));
			allowing(req).getParameter("RelayState"); will(returnValue(null));
			allowing(req).getParameter("SigAlg"); will(returnValue(URLDecoder.decode(Utils.getParameter("SigAlg", requestURL), "UTF-8")));
			allowing(req).getParameter("Signature"); will(returnValue(URLDecoder.decode(Utils.getParameter("Signature", requestURL), "UTF-8")));
			allowing(req).getMethod(); will(returnValue("GET"));
			allowing(req).getRequestURL(); will(returnValue(new StringBuffer(spMetadata.getSingleLogoutServiceHTTPRedirectLocation())));
			allowing(req).getQueryString(); will(returnValue(requestURL.substring(requestURL.indexOf('?') + 1)));
		}});
		
		logoutServiceHttpRedirectHandler.handleGet(ctx);
	}

	private LogoutResponse parseResponse() throws ParserConfigurationException,
			SAXException, IOException, UnsupportedEncodingException,
			UnmarshallingException {
		Document doc = parseBase64Encoded(Utils.getParameter("SAMLResponse", urlExtractor.getValue()));
		LogoutResponse lr = (LogoutResponse) Configuration.getUnmarshallerFactory().getUnmarshaller(doc.getDocumentElement()).unmarshall(doc.getDocumentElement());
		return lr;
	}
}
