package dk.itst.oiosaml.sp.util;

import java.io.*;
import java.net.URL;
import java.net.URLConnection;
import java.security.InvalidParameterException;
import java.util.List;

import javax.xml.namespace.QName;

import org.joda.time.DateTime;
import org.junit.Test;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Artifact;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.SessionIndex;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.ws.soap.soap11.Header;
import org.opensaml.ws.wssecurity.Created;
import org.opensaml.xml.AbstractXMLObject;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.impl.XSAnyBuilder;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.PGPData;
import org.opensaml.xml.signature.Signature;

import dk.itst.oiosaml.common.OIOSAMLConstants;
import dk.itst.oiosaml.common.SAMLUtil;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

import static org.junit.Assert.*;
import static org.junit.Assert.assertFalse;

public class SAMLUtilTest {

	static {
		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			throw new RuntimeException(e);
		}
	}
	
	@Test
	public void testBuildXMLObject() {
		XMLObject o = SAMLUtil.buildXMLObject(Assertion.class);
		assertNotNull(o);
		assertTrue(o instanceof Assertion);
		assertEquals(Assertion.DEFAULT_ELEMENT_NAME, o.getElementQName());
		try {
			SAMLUtil.buildXMLObject(TestObject.class);
			fail("test should be unknown");
		} catch (InvalidParameterException e) {}
	}
	
	public static class TestObject extends AbstractXMLObject {
		public static QName DEFAULT_ELEMENT_NAME = new QName("uri:test", "name", "t");
		public TestObject() {
			super("uri:test", "name", "t");
		}
		
		public List<XMLObject> getOrderedChildren() {
			return null;
		}		
	}

	@Test
	public void testCreateIssuer() {
		Issuer issuer = SAMLUtil.createIssuer("val");
		assertNotNull(issuer);
		assertEquals("val", issuer.getValue());
		
		issuer = SAMLUtil.createIssuer(null);
		assertNull(issuer);
	}

	@Test
	public void testCreateNameID() {
		NameID name = SAMLUtil.createNameID("name");
		assertNotNull(name);
		assertEquals("name", name.getValue());
		assertEquals(OIOSAMLConstants.PERSISTENT, name.getFormat());
	}

	@Test
	public void testCreateSessionIndex() {
		SessionIndex idx = SAMLUtil.createSessionIndex("idx");
		assertNotNull(idx);
		assertEquals("idx", idx.getSessionIndex());
		
		idx = SAMLUtil.createSessionIndex(null);
		assertNull(idx.getSessionIndex());
	}

	@Test
	public void testCreateSubject() {
		DateTime dateTime = new DateTime();
		Subject sub = SAMLUtil.createSubject("name", "url", dateTime);
		assertNotNull(sub);
		assertEquals("name", sub.getNameID().getValue());
		assertEquals(1, sub.getSubjectConfirmations().size());
		assertEquals(OIOSAMLConstants.METHOD_BEARER, sub.getSubjectConfirmations().get(0).getMethod());
		assertEquals("url", sub.getSubjectConfirmations().get(0).getSubjectConfirmationData().getRecipient());
		assertEquals(dateTime.toDate().getTime(), sub.getSubjectConfirmations().get(0).getSubjectConfirmationData().getNotOnOrAfter().toDate().getTime());
		assertNull(sub.getSubjectConfirmations().get(0).getSubjectConfirmationData().getNotBefore());
		assertNull(sub.getSubjectConfirmations().get(0).getSubjectConfirmationData().getAddress());
		assertNotNull(sub.getSubjectConfirmations().get(0).getSubjectConfirmationData().getIDIndex());
	}

	@Test
	public void testCreateAuthnContext() {
		AuthnContext ac = SAMLUtil.createAuthnContext("ref");
		assertNotNull(ac);
		assertNull(ac.getAuthContextDecl());
		assertTrue(ac.getAuthenticatingAuthorities().isEmpty());
		assertNull(ac.getAuthnContextDeclRef());
		
		AuthnContextClassRef cr = ac.getAuthnContextClassRef();
		assertNotNull(cr);
		assertEquals("ref", cr.getAuthnContextClassRef());
	}

	@Test
	public void testCreateAudienceCondition() {
		Conditions ac = SAMLUtil.createAudienceCondition("uri");
		assertNotNull(ac);
		assertEquals(1, ac.getConditions().size());
		assertNull(ac.getNotBefore());
		assertNull(ac.getNotOnOrAfter());
		assertNull(ac.getProxyRestriction());
		assertNull(ac.getOneTimeUse());
		
		AudienceRestriction ar = ac.getAudienceRestrictions().get(0);
		assertEquals(1, ar.getAudiences().size());
		Audience audience = ar.getAudiences().get(0);
		assertEquals("uri", audience.getAudienceURI());
	}

	@Test
	public void testCreateArtifact() {
		Artifact a = SAMLUtil.createArtifact("value");
		assertNotNull(a);
		assertEquals("value", a.getArtifact());
		
		a = SAMLUtil.createArtifact(null);
		assertNull(a.getArtifact());
	}

	@Test
	public void testCreateStatus() {
		Status s = SAMLUtil.createStatus("status");
		assertNotNull(s);
		assertNull(s.getStatusDetail());
		assertNull(s.getStatusMessage());
		assertNotNull(s.getStatusCode());
		
		assertEquals("status", s.getStatusCode().getValue());
	}

	@Test
	public void testCreateSignature() {
		Signature s = SAMLUtil.createSignature("key");
		assertNotNull(s);
		assertNull(s.getCanonicalizationAlgorithm());
		assertTrue(s.getContentReferences().isEmpty());
		assertNull(s.getHMACOutputLength());
		assertNull(s.getSignatureAlgorithm());
		assertNull(s.getSigningCredential());
		
		KeyInfo ki = s.getKeyInfo();
		assertNotNull(ki);
		assertTrue(ki.getAgreementMethods().isEmpty());
		assertTrue(ki.getEncryptedKeys().isEmpty());
		assertNull(ki.getID());
		assertTrue(ki.getMgmtDatas().isEmpty());
		assertTrue(ki.getPGPDatas().isEmpty());
		assertTrue(ki.getRetrievalMethods().isEmpty());
		assertTrue(ki.getSPKIDatas().isEmpty());
		assertTrue(ki.getX509Datas().isEmpty());
		assertTrue(ki.getKeyValues().isEmpty());
		
		assertEquals(1, ki.getKeyNames().size());
		
		assertEquals("key", ki.getKeyNames().get(0).getValue());
	}

	@Test
	public void testUnmarshallElement() throws IOException {
		XMLObject xo = SAMLUtil.unmarshallElement(getClass().getResourceAsStream("/assertion.xml"));
		assertTrue(xo instanceof Assertion);
		
		try {
			SAMLUtil.unmarshallElement(new ByteArrayInputStream("test".getBytes()));
			fail("file should not be found");
		} catch (IllegalArgumentException e) {}
	}

	@Test(expected=RuntimeException.class)
	public void testUnmarshallElementFromString() {
		XMLObject xo = SAMLUtil.unmarshallElementFromString("<saml:Assertion Version=\"2.0\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"></saml:Assertion>");
		assertTrue(xo instanceof Assertion);
		
		SAMLUtil.unmarshallElementFromString("<invalid>");
	}
	
	@Test(expected=RuntimeException.class)
	public void testUnmarshallElementFromFile() throws IOException {
		File file = File.createTempFile("test", ".xml");
		FileOutputStream os = new FileOutputStream(file);
		os.write("<saml:Assertion Version=\"2.0\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"></saml:Assertion>".getBytes());
		os.close();
		
		XMLObject xo = SAMLUtil.unmarshallElementFromFile(file.getAbsolutePath());
		assertTrue(xo instanceof Assertion);
		
		SAMLUtil.unmarshallElementFromFile("/test/temp");
	}

	@Test
	public void testGetSAMLObjectAsPrettyPrintXML() {
		Artifact a = SAMLUtil.createArtifact("a");
		String pretty = SAMLUtil.getSAMLObjectAsPrettyPrintXML(a);
		assertNotNull(pretty);
		assertEquals("<?xml version=\"1.0\" encoding=\"UTF-8\"?><saml2p:Artifact xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\">a</saml2p:Artifact>", pretty.trim().replaceAll("\n", ""));
		
		try {
			SAMLUtil.getSAMLObjectAsPrettyPrintXML(null);
		} catch (IllegalArgumentException e) {}
	}

	@Test
	public void testGetFirstElement() {
		XSAny h = new XSAnyBuilder().buildObject(Endpoint.TYPE_NAME);
		
		h.getUnknownXMLObjects().add(SAMLUtil.buildXMLObject(Header.class));
		h.getUnknownXMLObjects().add(SAMLUtil.buildXMLObject(PGPData.class));
		
		assertNull(SAMLUtil.getFirstElement(h, Created.class));
		assertNotNull(SAMLUtil.getFirstElement(h, Header.class));
		
		assertNull(SAMLUtil.getFirstElement(null, Created.class));
	}

	// TODO: the external file (note.xml) is not valid, so this test is no longer working
//    @Test
    public void testXXEPrevention() {
        // Arrange
        // Get external xml and test it indeed does exist. Hereafter test that is is not present in the loaded xml.
        InputStream in = null;
        try {
            String urlString = "http://www.w3schools.com/xml/note.xml";
            URL url = new URL(urlString);
            URLConnection conn = url.openConnection();
            in = conn.getInputStream();
        } catch (IOException e) {
            assertFalse("External resource was not found!", true);
        }
        Element externalElement = SAMLUtil.loadElement(in);
        String externalElementAsString = XMLHelper.prettyPrintXML(externalElement);

        // Act
        Element orig = SAMLUtil.loadElement(getClass().getResourceAsStream("/assertionWithExternalEntity.xml"));

        // Assert
        assertTrue("External entity did not include the expected text", externalElementAsString.contains("Don't forget me this weekend!"));
        assertFalse("External entities has not been disabled. XXE attack is therefore possible.", orig.getTextContent().contains("Don't forget me this weekend!"));
    }
}
