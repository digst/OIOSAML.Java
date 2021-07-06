/*
 * The contents of this file are subject to the Mozilla Public 
 * License Version 1.1 (the "License"); you may not use this 
 * file except in compliance with the License. You may obtain 
 * a copy of the License at http://www.mozilla.org/MPL/
 * 
 * Software distributed under the License is distributed on an 
 * "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, either express 
 * or implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 *
 * The Original Code is OIOSAML Java Service Provider.
 * 
 * The Initial Developer of the Original Code is Trifork A/S. Portions 
 * created by Trifork A/S are Copyright (C) 2008 Danish National IT 
 * and Telecom Agency (http://www.itst.dk). All Rights Reserved.
 * 
 * Contributor(s):
 *   Joakim Recht <jre@trifork.com>
 *   Rolf Njor Jensen <rolf@trifork.com>
 *
 */
package dk.itst.oiosaml.sp.model;

import static dk.itst.oiosaml.sp.service.TestHelper.validateUrlSignature;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.zip.DataFormatException;

import javax.xml.parsers.ParserConfigurationException;

import org.junit.Test;
import org.opensaml.Configuration;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.xml.io.UnmarshallingException;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.sp.NameIDFormat;
import dk.itst.oiosaml.sp.service.AbstractServiceTests;
import dk.itst.oiosaml.sp.service.TestHelper;
import dk.itst.oiosaml.sp.service.util.Utils;


public class OIOAuthnRequestTest extends AbstractServiceTests {

	@Test
	public void getRedirectUrl() throws NoSuchAlgorithmException, NoSuchProviderException, URISyntaxException, DataFormatException, IOException, ParserConfigurationException, SAXException, UnmarshallingException, InvalidKeyException, SignatureException {
		OIOAuthnRequest request = OIOAuthnRequest.buildAuthnRequest("http://ssoServiceLocation", "spEntityId", SAMLConstants.SAML2_ARTIFACT_BINDING_URI, handler, "state", "http://localhost");
		String url = request.getRedirectURL(credential);
		
		URI u = new URI(url);
		assertEquals("ssoServiceLocation", u.getHost());
		assertNotNull(Utils.getParameter("RelayState", url));

		String req = Utils.getParameter("SAMLRequest", url);
		assertNotNull(req);

		// check the request document
		Document document = TestHelper.parseBase64Encoded(req, true);
		
		AuthnRequest authRequest = (AuthnRequest) Configuration.getUnmarshallerFactory().getUnmarshaller(document.getDocumentElement()).unmarshall(document.getDocumentElement());
		assertEquals(SAMLConstants.SAML2_ARTIFACT_BINDING_URI, authRequest.getProtocolBinding());
		assertEquals("spEntityId", authRequest.getIssuer().getValue());
		assertEquals("http://ssoServiceLocation", authRequest.getDestination());
		
		validateUrlSignature(credential, url, req, "SAMLRequest");
	}

	@Test
	public void testSetNameIDPolicy() throws Exception {
		AuthnRequest ar = SAMLUtil.buildXMLObject(AuthnRequest.class);
		ar.setIssuer(SAMLUtil.createIssuer("issuer"));
		
		OIOAuthnRequest r = new OIOAuthnRequest(ar, "state");
		r.setNameIDPolicy(null, true);
		
		assertNull(ar.getNameIDPolicy());
		
		try {
			r.setNameIDPolicy("stupid", false);
			fail("invalid format");
		} catch (IllegalArgumentException e) {}
		
		r.setNameIDPolicy("persistent", true);
		assertNotNull(ar.getNameIDPolicy());
		assertEquals(NameIDFormat.PERSISTENT.getFormat(), ar.getNameIDPolicy().getFormat());
		assertTrue(ar.getNameIDPolicy().getAllowCreate());
		assertEquals("issuer", ar.getNameIDPolicy().getSPNameQualifier());
	}
}
