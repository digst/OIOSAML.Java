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

import org.junit.Test;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.StatusCode;

import com.gargoylesoftware.htmlunit.Page;
import com.gargoylesoftware.htmlunit.WebAssert;
import com.gargoylesoftware.htmlunit.WebRequestSettings;
import com.gargoylesoftware.htmlunit.html.HtmlPage;

public class LoginTest extends IntegrationTests {

	@Test
	public void testRedirect() throws Exception {
		RedirectRefreshHandler refreshHandler = new RedirectRefreshHandler();
		client.setRefreshHandler(refreshHandler);
		HtmlPage redirect = (HtmlPage) client.getPage(BASE + "/sp/priv1.jsp");
		assertEquals(200, redirect.getWebResponse().getStatusCode());
		assertTrue(refreshHandler.url.toString().startsWith(idpMetadata.getFirstMetadata().getSingleSignonServiceLocation(SAMLConstants.SAML2_REDIRECT_BINDING_URI)));
	}

	@Test
	public void testLoginResponse_IT_LOGON_1() throws Exception {
		client.getPage(BASE + "/sp/priv1.jsp");

		WebRequestSettings req = buildResponse(StatusCode.SUCCESS_URI, 2);
		Page responsePage = client.getPage(req);
		assertEquals(302, responsePage.getWebResponse().getStatusCode());
		assertEquals(BASE + "/sp/priv1.jsp", responsePage.getWebResponse().getResponseHeaderValue("Location"));
		
		HtmlPage loggedInPage = (HtmlPage) client.getPage(responsePage.getWebResponse().getResponseHeaderValue("Location"));
		WebAssert.assertTextPresent(loggedInPage, "joetest");
	}

	@Test
	public void testAssuranceLevelTooLow_IT_LOA_1() throws Exception {
		client.getPage(BASE + "/sp/priv1.jsp");

		WebRequestSettings req = buildResponse(StatusCode.SUCCESS_URI, 1);
		Page responsePage = client.getPage(req);
		assertEquals(302, responsePage.getWebResponse().getStatusCode());
		assertEquals(BASE + "/sp/priv1.jsp", responsePage.getWebResponse().getResponseHeaderValue("Location"));
		
		HtmlPage loggedInPage = (HtmlPage) client.getPage(responsePage.getWebResponse().getResponseHeaderValue("Location"));
		WebAssert.assertTextPresent(loggedInPage, "Assurance level too low");
		
		handler.url = null;
		client.getPage(BASE + "/sp/priv1.jsp");
		assertNotNull("User should be logged out", handler.url);
	}

	@Test
	public void testLoginFailure() throws Exception {
		client.getPage(BASE + "/sp/priv1.jsp");
		WebRequestSettings req = buildResponse(StatusCode.RESPONDER_URI, 2);
		HtmlPage responsePage = (HtmlPage) client.getPage(req);
		WebAssert.assertTextPresent(responsePage, StatusCode.RESPONDER_URI);
	}
}
