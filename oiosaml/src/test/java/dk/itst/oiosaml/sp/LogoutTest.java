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
package dk.itst.oiosaml.sp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.joda.time.DateTime;
import org.junit.Test;
import org.opensaml.Configuration;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.StatusCode;
import org.w3c.dom.Document;

import com.gargoylesoftware.htmlunit.Page;
import com.gargoylesoftware.htmlunit.WebRequestSettings;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.sp.model.OIOLogoutRequest;
import dk.itst.oiosaml.sp.model.OIOLogoutResponse;
import dk.itst.oiosaml.sp.service.TestHelper;
import dk.itst.oiosaml.sp.service.util.Utils;

public class LogoutTest extends IntegrationTests {
	
	@Test
	public void testSingleLogout_IT_SLO_1() throws Exception {
		login();
		Page logoutPage = client.getPage(BASE + "/saml/Logout");
		assertEquals(302, logoutPage.getWebResponse().getStatusCode());
		String logoutRedirect = logoutPage.getWebResponse().getResponseHeaderValue("Location");
        assertTrue(logoutRedirect + " did not start with: " + idpMetadata.getFirstMetadata().getSingleLogoutServiceLocation(), logoutRedirect.startsWith(idpMetadata.getFirstMetadata().getSingleLogoutServiceLocation()));

		handler.url = null;
		client.getPage(BASE + "/sp/priv1.jsp");
		assertNotNull(handler.url);
		assertTrue(handler.url.toString().startsWith(idpMetadata.getFirstMetadata().getSingleSignonServiceLocation(SAMLConstants.SAML2_REDIRECT_BINDING_URI)));
		
		Document document = TestHelper.parseBase64Encoded(Utils.getParameter("SAMLRequest", logoutRedirect));
		LogoutRequest lr = (LogoutRequest) Configuration.getUnmarshallerFactory().getUnmarshaller(document.getDocumentElement()).unmarshall(document.getDocumentElement());
		assertEquals("joetest", lr.getNameID().getValue());
		
		OIOLogoutResponse response = OIOLogoutResponse.fromRequest(new OIOLogoutRequest(lr), StatusCode.SUCCESS_URI, null, idpMetadata.getFirstMetadata().getEntityID(), spMetadata.getSingleLogoutServiceHTTPRedirectResponseLocation());
		String redirectURL = response.getRedirectURL(credential, Utils.getParameter("RelayState", handler.url.toString()));
		
		Page responsePage = client.getPage(redirectURL);
		assertEquals(302, responsePage.getWebResponse().getStatusCode());
		assertEquals("http://localhost:8808/saml", responsePage.getWebResponse().getResponseHeaderValue("Location"));
	}
	
	@Test
	public void testIdpInitiatedLogout_IT_SLO_2() throws Exception {
		login();

		LogoutRequest lr = SAMLUtil.buildXMLObject(LogoutRequest.class);
		lr.setID(Utils.generateUUID());
		lr.setIssuer(SAMLUtil.createIssuer(idpMetadata.getFirstMetadata().getEntityID()));
		lr.setDestination(spMetadata.getSingleLogoutServiceHTTPRedirectLocation());
		lr.setIssueInstant(new DateTime());
		lr.setNameID(SAMLUtil.createNameID("joetest"));
		OIOLogoutRequest req = new OIOLogoutRequest(lr);
		String redirectUrl = req.getRedirectRequestURL(credential);
		
		System.out.println(redirectUrl);
		Page responsePage = client.getPage(redirectUrl);
		assertEquals(302, responsePage.getWebResponse().getStatusCode());
		
	}
	
	private void login() throws Exception {
		client.getPage(BASE + "/sp/priv1.jsp");
		
		WebRequestSettings req = buildResponse(StatusCode.SUCCESS_URI, 2);
		client.getPage(req);
	}
}
