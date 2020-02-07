package dk.itst.oiosaml.sp.model;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;

import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.core.ArtifactResponse;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.encryption.Encrypter;
import org.opensaml.saml2.encryption.Encrypter.KeyPlacement;
import org.opensaml.xml.encryption.EncryptionConstants;
import org.opensaml.xml.encryption.EncryptionException;
import org.opensaml.xml.encryption.EncryptionParameters;
import org.opensaml.xml.encryption.KeyEncryptionParameters;
import org.opensaml.xml.security.SecurityTestHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.sp.AbstractTests;
import dk.itst.oiosaml.sp.model.validation.ValidationException;
import dk.itst.oiosaml.sp.service.TestHelper;
import dk.itst.oiosaml.sp.service.session.SingleVMSessionHandler;

@SuppressWarnings("deprecation")
public class OIOResponseTest extends AbstractTests {

	private Response srt;
	private String destination = "destination";
	private String issuerValue = "issuer value";
	private OIOResponse response;
	private X509Certificate cert;
	private Credential credential;
	
	@Before
	public void setUp() throws Exception {
		srt = (Response) ((ArtifactResponse)SAMLUtil.unmarshallElement(getClass().getResourceAsStream("/response.xml"))).getMessage();
		srt.setDestination(destination);
		srt.getIssuer().setValue(issuerValue);
		
		response = new OIOResponse(srt);

		credential = TestHelper.getCredential();
		cert = TestHelper.getCertificate(credential);
		
		response.sign(credential);
	}

	@Test
	public void testIsDestinationOK() {
		assertTrue(response.isDestinationOK(destination));
		assertFalse(response.isDestinationOK(".kfsjf"));
	}

	@Test
	public void testIsIssuerOK() {
		assertTrue(response.isIssuerOK(issuerValue));
		assertFalse(response.isIssuerOK(null));
		assertFalse(response.isIssuerOK("lsdkfj"));
		srt.setIssuer(null);
		assertFalse(response.isIssuerOK(issuerValue));
	}
	
	@Test
	public void testGetOriginatingIssuerId() throws Exception {
		srt.setInResponseTo(null);
		srt.setIssuer(null);
		
		SingleVMSessionHandler handler = new SingleVMSessionHandler();
		assertEquals(srt.getAssertions().get(0).getIssuer().getValue(), response.getOriginatingIdpEntityId(handler));

		srt.getAssertions().get(0).setIssuer(null);
		try {
			response.getOriginatingIdpEntityId(handler);
			fail("No issuer in assertion");
		} catch (ValidationException e) {}
		
		srt.setInResponseTo("testid");
		handler.registerRequest("testid", "issuer");
		assertEquals("issuer", response.getOriginatingIdpEntityId(handler));
		
	}
	
	@Test(expected=ValidationException.class)
	public void testGetOriginatingShouldFailOnNoAssertions() throws Exception {
		srt.getAssertions().clear();
		srt.setInResponseTo(null);
		srt.setIssuer(null);
		response.getOriginatingIdpEntityId(new SingleVMSessionHandler());
	}
	
	@Test
	public void testValidateResponse() throws Exception {
		response.validateResponse(srt.getDestination(), cert, false); 
	} 
	
	@Test(expected=ValidationException.class)
	public void validateFailOnWrongStatus() throws Exception {
		srt.setStatus(SAMLUtil.createStatus(StatusCode.AUTHN_FAILED_URI));
		response.validateResponse(srt.getDestination(), cert, false);
		fail("invalid status");
	}

	@Test(expected=ValidationException.class)
	public void validateFailOnWrongDestination() throws Exception {
		response.validateResponse("blargh", cert, false);
	}
	
	@Test(expected=ValidationException.class)
	public void validateFailOnNoAssertions() throws Exception {
		srt.getAssertions().clear();
		response.validateResponse(srt.getDestination(), cert, false);
	}

	@Test(expected=ValidationException.class)
	public void validateFailOnNoSignatures() throws Exception {
		srt.setSignature(null);
		srt.getAssertions().get(0).setSignature(null);
		
		response.validateResponse(srt.getDestination(), cert, false);
		response.validateAssertionSignature(cert);
	}
	
	@Test
	public void validateSignatureOnAssertion() throws Exception {
		srt.setSignature(null);
		response.getAssertion().sign(credential);
		response.validateResponse(srt.getDestination(), cert, false);
	}
	
	
	@Test
	public void validatePassiveAllowed() throws Exception {
		srt.getAssertions().clear();
		srt.setStatus(SAMLUtil.createStatus(StatusCode.RESPONDER_URI));
		StatusCode code = SAMLUtil.buildXMLObject(StatusCode.class);
		code.setValue(StatusCode.NO_PASSIVE_URI);
		srt.getStatus().getStatusCode().setStatusCode(code);
		
		Element elm = SAMLUtil.marshallObject(srt);
		srt.setDOM(elm);
        OIOResponse oioResponse = new OIOResponse(srt);
        oioResponse.sign(credential);

		response.validateResponse(srt.getDestination(), cert, true);
	}
	
	@Test
	public void isPassiveIgnoresOuterStatus() throws Exception {
		srt.getAssertions().clear();
		srt.setStatus(SAMLUtil.createStatus(StatusCode.REQUESTER_URI));
		StatusCode code = SAMLUtil.buildXMLObject(StatusCode.class);
		code.setValue(StatusCode.NO_PASSIVE_URI);
		srt.getStatus().getStatusCode().setStatusCode(code);

		assertTrue(response.isPassive());
	}
	
	@Test(expected=ValidationException.class)
	public void validatePassiveNotAllowed() throws Exception {
		srt.getAssertions().clear();
		srt.setStatus(SAMLUtil.createStatus(StatusCode.RESPONDER_URI));
		StatusCode code = SAMLUtil.buildXMLObject(StatusCode.class);
		code.setValue(StatusCode.NO_PASSIVE_URI);
		srt.getStatus().getStatusCode().setStatusCode(code);
		
		response.validateResponse(srt.getDestination(), cert, false);
	}
	
	
	@Test
	public void testGetAssertion() throws Exception {
		assertNotNull(response.getAssertion());
		
		OIOAssertion ass = new OIOAssertion(srt.getAssertions().get(0));
		assertEquals(ass.toXML(), response.getAssertion().toXML());
	}

	@Test(expected=ValidationException.class)
	public void failIfAssertionIsNotEncrypted() throws Exception {
		response.decryptAssertion(credential, false);
	}
	
	@Test
	public void allowUnencryptedAssertion() throws Exception {
		response.decryptAssertion(credential, true);
	}
	
	@Test
	public void testGetEncryptedAssertion() throws Exception {
		
        EncryptedAssertion encrypted = encryptAssertion(true);
        srt.getAssertions().clear();
        srt.getEncryptedAssertions().add(encrypted);
        
        response = new OIOResponse((Response) SAMLUtil.unmarshallElementFromString(response.toXML()));

        try {
        	response.getAssertion();
        	fail("Response should not contain an assertion");
        } catch (RuntimeException e) {}
        
        assertEquals(0, response.getResponse().getAssertions().size());
        response.decryptAssertion(credential, false);
        assertNotNull(response.getAssertion());
        assertEquals(1, response.getResponse().getAssertions().size());
        
        try {
	        Credential otherCredential = TestHelper.getCredential();
	        response.decryptAssertion(otherCredential, false);
	        fail("Should fail, trying with wrong key");
        } catch (ValidationException e) {}
	}
	
	@Test
	public void testEncryptedAssertionWithRetrievalMethod() throws Exception {
        EncryptedAssertion encrypted = encryptAssertion(false);
        srt.getAssertions().clear();
        srt.getEncryptedAssertions().add(encrypted);
        
        System.out.println(XMLHelper.nodeToString(SAMLUtil.marshallObject(encrypted)));

        response.decryptAssertion(credential, false);
        assertNotNull(response.getAssertion());
	}

	@Test
	public void testValidateSignatureAfterDecryption() throws Exception {
		response.getAssertion().sign(credential);
		
		EncryptedAssertion encrypted = encryptAssertion(true);
		srt.getAssertions().clear();
        srt.getEncryptedAssertions().add(encrypted);
        
		
		response.decryptAssertion(credential, false);
		assertTrue(response.getAssertion().verifySignature(credential.getPublicKey()));
	}

	private EncryptedAssertion encryptAssertion(boolean inline) throws NoSuchAlgorithmException, NoSuchProviderException, EncryptionException {
		Credential symmetricCredential = SecurityTestHelper.generateKeyAndCredential(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128);
        assertNotNull(symmetricCredential.getSecretKey());
		
        EncryptionParameters encParams = new EncryptionParameters();
        encParams.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128);
        encParams.setEncryptionCredential(symmetricCredential);
        
        KeyEncryptionParameters kek = new KeyEncryptionParameters();
        
        kek.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSA15);
        kek.setEncryptionCredential(this.credential);
        
        
        Encrypter encrypter = new Encrypter(encParams, kek);
        if (inline) {
        	encrypter.setKeyPlacement(KeyPlacement.INLINE);
        } else {
        	encrypter.setKeyPlacement(KeyPlacement.PEER);
        }
        
        EncryptedAssertion encrypted = encrypter.encrypt(response.getAssertion().getAssertion());
		return encrypted;
	}
}
