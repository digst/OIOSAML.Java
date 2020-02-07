package dk.itst.oiosaml.sp.model;

import static dk.itst.oiosaml.sp.service.TestHelper.parseBase64Encoded;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.net.URLDecoder;

import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.Configuration;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.SessionIndex;
import org.opensaml.xml.security.credential.Credential;
import org.w3c.dom.Document;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.sp.service.AbstractServiceTests;
import dk.itst.oiosaml.sp.service.TestHelper;
import dk.itst.oiosaml.sp.service.util.Constants;
import dk.itst.oiosaml.sp.service.util.Utils;
import dk.itst.oiosaml.sp.util.LogoutRequestValidationException;

public class OIOLogoutRequestTest extends AbstractServiceTests {
	
	private LogoutRequest lr;
	private OIOLogoutRequest lh;
	
	@Before
	public void setUp() {
		lr = SAMLUtil.buildXMLObject(LogoutRequest.class);
		lh = new OIOLogoutRequest(lr);
	}
	

	@Test
	public void testGetSessionIndex() {
		assertNull(lh.getSessionIndex());

		SessionIndex idx = SAMLUtil.createSessionIndex("val");
		lr.getSessionIndexes().add(idx);
		
		assertEquals("val", lh.getSessionIndex());
	}

	@Test
	public void testIsSessionIndexOK() {
		assertFalse(lh.isSessionIndexOK("idx"));
		lr.getSessionIndexes().add(SAMLUtil.createSessionIndex("idx"));
		
		assertTrue(lh.isSessionIndexOK("idx"));
	}

	@Test
	public void testValidateLogoutRequest() throws Exception {
		String location = "http://logoutServiceLocation";
		String issuer = "entityId";
		String url = OIOLogoutRequest.buildLogoutRequest(session, location, issuer, handler).getRedirectRequestURL(credential);
		
		Document doc = parseBase64Encoded(Utils.getParameter("SAMLRequest", url));
		LogoutRequest lr = (LogoutRequest) Configuration.getUnmarshallerFactory().getUnmarshaller(doc.getDocumentElement()).unmarshall(doc.getDocumentElement());
		lh = new OIOLogoutRequest(lr);
		
		try {
			lh.validateRequest("sig", url.substring(url.indexOf('?') + 1), credential.getPublicKey(), "dest", "issuer");
			fail();
		} catch (LogoutRequestValidationException e) {
			assertEquals(e.getMessage(), 3, e.getErrors().size());
		}
		
		try {
			lh.validateRequest(URLDecoder.decode(Utils.getParameter("Signature", url), "UTF-8"), url.substring(url.indexOf('?') + 1), credential.getPublicKey(), "dest", "issuer");
			fail();
		} catch (LogoutRequestValidationException e) {
			assertEquals(2, e.getErrors().size());
		}
		
		try {
			lh.validateRequest(URLDecoder.decode(Utils.getParameter("Signature", url), "UTF-8"), url.substring(url.indexOf('?') + 1), credential.getPublicKey(),location, "issuer");
			fail();
		} catch (LogoutRequestValidationException e) {
			assertEquals(1, e.getErrors().size());
		}
		
		lr.setNotOnOrAfter(new DateTime().minusMinutes(1));
		try {
			lh.validateRequest(URLDecoder.decode(Utils.getParameter("Signature", url), "UTF-8"), url.substring(url.indexOf('?') + 1), credential.getPublicKey(),location, lr.getIssuer().getValue());
			fail("message is expired");
		} catch (LogoutRequestValidationException e) {
			assertEquals(1, e.getErrors().size());
		}

		lr.setNotOnOrAfter(new DateTime().plusHours(1));
		lh.validateRequest(URLDecoder.decode(Utils.getParameter("Signature", url), "UTF-8"), url.substring(url.indexOf('?') + 1), credential.getPublicKey(),location, issuer);
	}

	@Test
	public void testGetRedirectRequestUrl() throws Exception {
		lr.setDestination("http://dest");
		
		Credential cred = TestHelper.getCredential();
		String url = lh.getRedirectRequestURL(cred);
		
		String req = Utils.getParameter(Constants.SAML_SAMLREQUEST, url);
		
		TestHelper.validateUrlSignature(cred, url, req, Constants.SAML_SAMLREQUEST);
		
		Document document = TestHelper.parseBase64Encoded(req);
		LogoutRequest logoutRequest = (LogoutRequest) Configuration.getUnmarshallerFactory().getUnmarshaller(document.getDocumentElement()).unmarshall(document.getDocumentElement());
		assertEquals(lr.getDestination(), logoutRequest.getDestination());
	}
	
	
	@Test
	public void testBuildLogoutRequest() throws Exception {
		setHandler();
		OIOLogoutRequest lr = OIOLogoutRequest.buildLogoutRequest(session, "http://logout", "issuer", handler);
		
		assertEquals("issuer", lr.getIssuer());
		assertNotNull(lr.getID());

		Credential cred = TestHelper.getCredential();
		String url = lr.getRedirectRequestURL(cred);
		String req = Utils.getParameter(Constants.SAML_SAMLREQUEST, url);
		Document document = TestHelper.parseBase64Encoded(req);
		LogoutRequest logoutRequest = (LogoutRequest) Configuration.getUnmarshallerFactory().getUnmarshaller(document.getDocumentElement()).unmarshall(document.getDocumentElement());

		
		assertEquals("http://logout", logoutRequest.getDestination());
		assertNotNull(logoutRequest.getIssueInstant());
		assertFalse(logoutRequest.getSessionIndexes().isEmpty());
	}
}
