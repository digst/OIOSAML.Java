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
 *
 */

package dk.itst.oiosaml.discovery.service;

import static org.junit.Assert.assertTrue;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URLEncoder;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jmock.Expectations;
import org.jmock.Mockery;
import org.junit.Before;
import org.junit.Test;


public class DiscoveryServletTest {
	
	private Mockery context = new Mockery();
	private HttpServletRequest req;
	private HttpServletResponse res;
	private DiscoveryServlet servlet;

	@Before
	public void setUp() {
		req = context.mock(HttpServletRequest.class);
		res = context.mock(HttpServletResponse.class);
		servlet = new DiscoveryServlet();
		context.checking(new Expectations() {{
			allowing(req).getRemoteAddr(); will(returnValue("127.0.0.1"));
		}});
	}
	
	@Test
	public void failWhenNoReferer() throws Exception {
		context.checking(new Expectations() {{
			atLeast(1).of(req).getParameter(DiscoveryServlet.REFERER_PARAMETER); will(returnValue(null));
			one(res).sendError(with(equal(HttpServletResponse.SC_PRECONDITION_FAILED)), with(any(String.class)));
		}});
		
		servlet.doGet(req, res);
		context.assertIsSatisfied();
	}

	@Test
	public void returnEmptyWhenNoCookie() throws Exception {
		final StringWriter sw = new StringWriter();
		context.checking(new Expectations() {{
			atLeast(1).of(req).getParameter(DiscoveryServlet.REFERER_PARAMETER); will(returnValue("http://localhost"));
			one(req).getCookies(); will(returnValue(new Cookie[0]));
			one(res).getWriter(); will(returnValue(new PrintWriter(sw)));
			one(res).setContentType("text/html");
		}});
		servlet.doGet(req, res);
		
		assertTrue(sw.toString().indexOf("0;url=http://localhost?_saml_idp=") > -1);
		context.assertIsSatisfied();
	}
	
	@Test
	public void testRedirectWithSamlIdp() throws Exception {
		String idplist = Base64.encodeBytes("http://idp1.com".getBytes()) + " " + Base64.encodeBytes("http://idp2.com".getBytes());
		final Cookie[] c = new Cookie[] {
				new Cookie("_saml_idp", URLEncoder.encode(idplist, "UTF-8"))
		};
		c[0].setSecure(true);
		c[0].setPath("/");
		
		final StringWriter sw = new StringWriter();
		context.checking(new Expectations() {{
			atLeast(1).of(req).getParameter(DiscoveryServlet.REFERER_PARAMETER); will(returnValue("http://localhost"));
			one(req).getCookies(); will(returnValue(c));
			one(res).getWriter(); will(returnValue(new PrintWriter(sw)));
			one(res).setContentType("text/html");
		}});
		servlet.doGet(req, res);
		
		assertTrue(sw.toString().indexOf("0;url=http://localhost?_saml_idp=" + Base64.encodeBytes(URLEncoder.encode(idplist, "UTF-8").getBytes())) > -1);
		context.assertIsSatisfied();
	}	
}
