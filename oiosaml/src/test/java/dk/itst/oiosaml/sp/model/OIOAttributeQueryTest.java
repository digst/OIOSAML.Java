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
 *   Aage Nielsen <ani@openminds.dk> 
 *
 */
package dk.itst.oiosaml.sp.model;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import org.jmock.Expectations;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.w3c.dom.Element;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.sp.NameIDFormat;
import dk.itst.oiosaml.sp.metadata.IdpMetadata;
import dk.itst.oiosaml.sp.service.AbstractServiceTests;
import dk.itst.oiosaml.sp.service.TestHelper;
import dk.itst.oiosaml.sp.service.util.HttpSOAPClient;
import dk.itst.oiosaml.sp.service.util.SOAPClient;


public class OIOAttributeQueryTest extends AbstractServiceTests {
	
	private String dest;
	private String issuer;
	private OIOAttributeQuery q;
	
	@Before
	public void setUp() {
		dest = "https://saml-idp.trifork.com:9031/idp/attrsvc.ssaml2";
		issuer = "saml.jre-pc.trifork.com";
		q = OIOAttributeQuery.newQuery(dest, "joetest",NameIDFormat.X509SUBJECT, issuer);
	}

	@Test
	public void testNewQuery() throws Exception {
		assertEquals(dest, q.getDestination());
		assertNotNull(q.getID());
		assertEquals(issuer, q.getIssuer());
	}
	
	@Test
	public void testExecuteQuery() throws Exception {
		q.addAttribute("uid", null);
		Assertion assertion = TestHelper.buildAssertion(null, spMetadata.getEntityID());
		new OIOAssertion(assertion).sign(credential);

		Response response = TestHelper.buildResponse(assertion);
		Element element = SAMLUtil.marshallObject(response);
		final Response resp2 = (Response) SAMLUtil.unmarshallElement(element);

		final SOAPClient client = context.mock(SOAPClient.class);
		context.checking(new Expectations() {{
			one(client).wsCall(with(same(q)), with(equal(dest)), with(equal("username")), with(equal("password")), with(equal(true)));
			will(returnValue(resp2));
		}});
		OIOAssertion res = q.executeQuery(client, credential, "username", "password", true, idpMetadata.getFirstMetadata().getCertificates(), true);
		assertNotNull(res);
	}
	private KeyStore getKeystore(InputStream is) throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {
		KeyStore ks=KeyStore.getInstance("JKS");
		ks.load(is,"test".toCharArray());
		return ks;
	}

	public void testIntegration() throws Exception {
		q.addAttribute("uid", null);
		
		HttpSOAPClient client = new HttpSOAPClient();
		EntityDescriptor d = (EntityDescriptor) SAMLUtil.unmarshallElementFromFile("/tmp/env/metadata/IdP/IdPMetadata.xml.old");
		IdpMetadata md = new IdpMetadata(SAMLConstants.SAML20P_NS, d);
		
		InputStream streamToKeystore=new FileInputStream("/tmp/env/certificate/keystore");
		
		BasicX509Credential credential = credentialRepository.getCredential(getKeystore(streamToKeystore), "test");
		
		OIOAssertion res = q.executeQuery(client, credential, null, null, true, md.getFirstMetadata().getCertificates(), false);
		System.out.println(res.toXML());
	}
}
