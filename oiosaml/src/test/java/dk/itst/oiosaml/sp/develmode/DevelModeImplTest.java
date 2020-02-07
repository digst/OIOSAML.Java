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
 * created by Trifork A/S are Copyright (C) 2009 Danish National IT 
 * and Telecom Agency (http://www.itst.dk). All Rights Reserved.
 * 
 * Contributor(s):
 *   Joakim Recht <jre@trifork.com>
 *   Rolf Njor Jensen <rolf@trifork.com>
 *
 */
package dk.itst.oiosaml.sp.develmode;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.configuration.Configuration;
import org.jmock.Expectations;
import org.junit.Before;
import org.junit.Test;

import dk.itst.oiosaml.sp.UserAssertion;
import dk.itst.oiosaml.sp.UserAssertionHolder;
import dk.itst.oiosaml.sp.UserAssertionImpl;
import dk.itst.oiosaml.sp.UserAttribute;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.service.AbstractServiceTests;
import dk.itst.oiosaml.sp.service.TestHelper;
import dk.itst.oiosaml.sp.service.util.Constants;


public class DevelModeImplTest extends AbstractServiceTests {
	private Map<String, String> conf = new HashMap<String, String>();

	private DevelModeImpl dmi;
	private FilterChain chain;

	private Configuration cfg;
	@Before
	public void setup() {
		dmi = new DevelModeImpl();
		chain = context.mock(FilterChain.class);
		cfg = TestHelper.buildConfiguration(conf);
		UserAssertionHolder.set(null);
	}
	
	@Test
	public void testNotConfigured() throws Exception {
		expectNotLoggedIn();
		final StringWriter sw = new StringWriter();
		context.checking(new Expectations() {{
			one(res).setStatus(500);
			one(res).getWriter(); will(returnValue(new PrintWriter(sw)));
	        one(req).getServletPath(); will(returnValue("/Test"));
		}});
		expectCacheHeaders();
		dmi.doFilter(req, res, chain, cfg);
	}
	
    @Test
	public void testOneUserNoInteractions() throws Exception {
		expectNotLoggedIn();
		
		conf.put("oiosaml-sp.develmode.users", "test");
		
		expectDoFilter();
		
		dmi.doFilter(req, res, chain, cfg);
		
		assertNotNull(UserAssertionHolder.get());
		UserAssertion ua = UserAssertionHolder.get();
		
		assertEquals("test", ua.getSubject());
		assertEquals(0, ua.getAllAttributes().size());
	}
	
    @Test
	public void testUserAttributes() throws Exception {
		expectNotLoggedIn();
		conf.put("oiosaml-sp.develmode.users", "test");
		conf.put("oiosaml-sp.develmode.test.urn:oid:2.5.4.4", "testing");
		conf.put("oiosaml-sp.develmode.test.random", "value");
		conf.put("oiosaml-sp.develmode.test.multi", "value1, value2");
		
		expectDoFilter();
		
		dmi.doFilter(req, res, chain, cfg);
		
		UserAssertion ua = UserAssertionHolder.get();
		assertNotNull(ua);
		
		assertEquals(3, ua.getAllAttributes().size());
		assertEquals("testing", ua.getSurname());
		
		UserAttribute attr = ua.getAttribute("multi");
		assertNotNull(attr);
		assertEquals(2, attr.getValues().size());
		assertEquals("value1", attr.getValues().get(0));
		assertEquals("value2", attr.getValues().get(1));
	}

    @Test
	public void multipleUsernamesMustInteract() throws Exception {
		expectNotLoggedIn();
		
		conf.put("oiosaml-sp.develmode.users", "test,test2");
		
		final StringWriter sw = new StringWriter();
		context.checking(new Expectations() {{
			one(req).getParameter("__oiosaml_devel"); will(returnValue(null));
			one(res).getWriter(); will(returnValue(new PrintWriter(sw)));
			one(req).getParameterMap(); will(returnValue(new HashMap<String, String[]>()));
	        one(req).getServletPath(); will(returnValue("/Test"));
		}});
		expectCacheHeaders();
		dmi.doFilter(req, res, chain, cfg);
		
		assertNull(UserAssertionHolder.get());
	}
	
    @Test
	public void filterIfSessionExists() throws Exception {
		context.checking(new Expectations() {{
			one(session).getAttribute(Constants.SESSION_USER_ASSERTION); will(returnValue(new UserAssertionImpl(new OIOAssertion(TestHelper.buildAssertion("test", "test")))));
		}});
		expectDoFilter();
		
		dmi.doFilter(req, res, chain, cfg);
		assertNotNull(UserAssertionHolder.get());
	}
	
	private void expectDoFilter() throws IOException, ServletException {
		context.checking(new Expectations() {{
			one(chain).doFilter(with(any(HttpServletRequest.class)), with(equal(res)));
			one(session).setAttribute(with(equal(Constants.SESSION_USER_ASSERTION)), with(any(UserAssertion.class)));
			one(req).getServletPath(); will(returnValue("/Test"));
		}});
	}
	
	private void expectNotLoggedIn() {
		context.checking(new Expectations() {{
			one(session).getAttribute(Constants.SESSION_USER_ASSERTION); will(returnValue(null));
		}});
	}
	
}
