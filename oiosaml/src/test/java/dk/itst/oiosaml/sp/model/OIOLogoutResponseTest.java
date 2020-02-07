package dk.itst.oiosaml.sp.model;

import static dk.itst.oiosaml.sp.service.TestHelper.getCredential;
import static dk.itst.oiosaml.sp.service.TestHelper.parseBase64Encoded;
import static dk.itst.oiosaml.sp.service.TestHelper.validateUrlSignature;
import static org.junit.Assert.*;

import java.net.URI;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.opensaml.Configuration;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.security.credential.Credential;
import org.w3c.dom.Document;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.sp.model.OIOLogoutRequest;
import dk.itst.oiosaml.sp.model.OIOLogoutResponse;
import dk.itst.oiosaml.sp.service.AbstractServiceTests;
import dk.itst.oiosaml.sp.service.util.Utils;

public class OIOLogoutResponseTest extends AbstractServiceTests {
	
	private OIOLogoutRequest request;
	private OIOLogoutResponse response;

	@Before
	public void setUp() {
		request = OIOLogoutRequest.buildLogoutRequest(session, "http://logout", "entityId", handler);
		response = OIOLogoutResponse.fromRequest(request, "status", "consent", "entityId", "http://destination");
	}

	@Test
	public void testFromRequest() {
		assertNotNull(response);
		assertEquals(request.getID(), response.getInResponseTo());
	}

	@Test
	public void testToSoapEnvelope() {
		String xml = response.toSoapEnvelope();
		Envelope e = (Envelope) SAMLUtil.unmarshallElementFromString(xml);
		Body body = e.getBody();
		assertNotNull(body);
		
		List<XMLObject> objects = body.getUnknownXMLObjects();
		assertEquals(1, objects.size());
		assertTrue(objects.get(0) instanceof LogoutResponse);
		
	}

	@Test
	public void testGetRedirectResponseURL() throws Exception {
		Credential cred = getCredential();
		String url = response.getRedirectURL(cred, "relayState");
		
		assertNotNull(url);
		
		URI u = new URI(url);
		assertEquals("destination", u.getHost());

		String req = Utils.getParameter("SAMLResponse", url);
		assertNotNull(req);
		
		Document doc = parseBase64Encoded(req);
		LogoutResponse lr = (LogoutResponse) Configuration.getUnmarshallerFactory().getUnmarshaller(doc.getDocumentElement()).unmarshall(doc.getDocumentElement());
		assertEquals("entityId", lr.getIssuer().getValue());
		assertEquals("status", lr.getStatus().getStatusCode().getValue());
		assertEquals("consent", lr.getConsent());
		assertEquals(request.getID(), lr.getInResponseTo());
		assertEquals("http://destination", lr.getDestination());
		
		System.out.println(url);
		validateUrlSignature(cred, url, req, "SAMLResponse");
	}


}
