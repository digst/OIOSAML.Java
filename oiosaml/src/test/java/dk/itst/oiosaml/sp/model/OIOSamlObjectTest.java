package dk.itst.oiosaml.sp.model;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.joda.time.DateTime;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.util.Base64;
import org.w3c.dom.Element;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.sp.AbstractTests;
import dk.itst.oiosaml.sp.model.OIOSamlObject;
import dk.itst.oiosaml.sp.service.TestHelper;

public class OIOSamlObjectTest extends AbstractTests{

	private OIOSamlObject obj;
	private Assertion assertion;
	@Before
	public void setUp() throws Exception {
		assertion = (Assertion) SAMLUtil.unmarshallElement(getClass().getResourceAsStream("/assertion.xml"));
		obj = new OIOSamlObject(assertion);
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test(expected=IllegalArgumentException.class)
	public void testOIOSamlObject() {
		new OIOSamlObject(null);
	}

	@Test
	public void testToXML() {
		Element orig = SAMLUtil.loadElement(getClass().getResourceAsStream("/assertion.xml"));
		Element created = SAMLUtil.loadElementFromString(obj.toXML());
		assertTrue(orig.isEqualNode(created));
	}

	@Test
	public void testSign() throws Exception{
		assertion.setSignature(null);
		Credential credential = TestHelper.getCredential();
		obj.sign(credential);
		assertTrue(obj.hasSignature());
		assertTrue(obj.verifySignature(credential.getPublicKey()));
	}

	@Test
	public void testToBase64() {
		String encoded = obj.toBase64();
		assertEquals(obj.toXML(), new String(Base64.decode(encoded)));
	}

	@Test
	public void testHasSignature() {
		assertion.setSignature(SAMLUtil.createSignature("tes"));
		assertTrue(obj.hasSignature());
		assertion.setSignature(null);
		assertFalse(obj.hasSignature());
	}

	@Test
	public void testVerifySignature() throws Exception {
		Assertion a = (Assertion) SAMLUtil.unmarshallElementFromString("<saml:Assertion Version=\"2.0\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"></saml:Assertion>");
		
		Credential cred = TestHelper.getCredential();
		
		assertFalse(new OIOSamlObject(a).verifySignature(cred.getPublicKey()));
		
		Signature signature = SAMLUtil.createSignature("test");
		signature.setSigningCredential(cred);
		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
		signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		a.setSignature(signature);

		Configuration.getMarshallerFactory().getMarshaller(a).marshall(a);
		Signer.signObject(signature);
		
		assertTrue(new OIOSamlObject(a).verifySignature(cred.getPublicKey()));

		Credential cred2 = TestHelper.getCredential();
		assertFalse(new OIOSamlObject(a).verifySignature(cred2.getPublicKey()));
		
		
		a.setSubject(SAMLUtil.createSubject("test", "test", new DateTime()));
		Configuration.getMarshallerFactory().getMarshaller(a).marshall(a);

		assertFalse(new OIOSamlObject(a).verifySignature(cred.getPublicKey()));
	}

}
