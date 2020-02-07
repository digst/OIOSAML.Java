package dk.itst.oiosaml.sp.model;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;

import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.xml.security.credential.Credential;
import org.w3c.dom.Element;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.sp.AbstractTests;
import dk.itst.oiosaml.sp.model.OIOAuthnRequest;
import dk.itst.oiosaml.sp.service.TestHelper;

public class OIORequestTest extends AbstractTests{
	private OIOAuthnRequest request;
	private AuthnRequest ar;
	private Credential credential;
	
	@Before
	public void setUp() throws Exception {
		ar = (AuthnRequest) SAMLUtil.unmarshallElement(getClass().getResourceAsStream("/request.xml"));
		ar.getIssuer().setValue("issuerValue");
		
		this.request = new OIOAuthnRequest(ar, "state");
		
		credential = TestHelper.getCredential();

		this.request.sign(credential);
	}

	@Test
	public void testIsDestinationOK() {
		String destination = "https://saml-idp.trifork.com:9031/idp/SSO.saml2";
		
		assertFalse(request.isDestinationOK(null));
		assertTrue(request.isDestinationOK(destination));
		assertFalse(request.isDestinationOK("void"));
	}

	@Test
	public void testIsIssuerOK() {
		assertTrue(request.isIssuerOK("issuerValue"));
		assertFalse(request.isIssuerOK(null));
		assertFalse(request.isIssuerOK("lsdkfj"));
		ar.setIssuer(null);
		assertFalse(request.isIssuerOK("issuerValue"));
	}
	
	@Test
	public void testGetIssuer() throws Exception {
		assertEquals("issuerValue", request.getIssuer());
		ar.setIssuer(null);
		assertNull(request.getIssuer());
	}
	
	@Test
	public void testGetID() throws Exception {
		assertEquals(ar.getID(), request.getID());
	}
	
	@Test
	public void testValidateRequest() throws Exception {
		ArrayList<String> errors = new ArrayList<String>();
		request.validateRequest(request.getIssuer(), ar.getDestination(), credential.getPublicKey(), errors);
		assertEquals(0, errors.size());
		
		errors.clear();
		request.validateRequest(request.getIssuer(), "dest", credential.getPublicKey(), errors);
		assertEquals(1, errors.size());

		errors.clear();
		request.validateRequest("issuer", "dest", TestHelper.getCredential().getPublicKey(), errors);
		assertEquals(3, errors.size());
		
		errors.clear();
		ar.setSignature(null);
		request.validateRequest("issuer", "dest", TestHelper.getCredential().getPublicKey(), errors);
		assertEquals(2, errors.size());
	}

    @Test
    public void testValidateRequestNemIssuer() throws Exception {
        ArrayList<String> errors = new ArrayList<String>();

        errors.clear();
        ar.setIssuer(SAMLUtil.createIssuer("test"));
        Element elm = SAMLUtil.marshallObject(ar);
        ar.setDOM(elm);

        OIOAuthnRequest oioAuthnRequest = new OIOAuthnRequest(ar, "state");
        oioAuthnRequest.sign(credential);
        
        oioAuthnRequest.validateRequest("issuer", "dest", credential.getPublicKey(), errors);
        assertEquals(2, errors.size());
    }
}
