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
package dk.itst.oiosaml.sp.service.util;

import java.util.HashMap;

import org.apache.commons.configuration.Configuration;
import org.jmock.Expectations;
import org.junit.Before;
import org.junit.Test;

import dk.itst.oiosaml.sp.service.AbstractServiceTests;
import dk.itst.oiosaml.sp.service.RequestContext;
import dk.itst.oiosaml.sp.service.TestHelper;
import dk.itst.oiosaml.sp.service.session.Request;


public class HTTPUtilsTest extends AbstractServiceTests {
	
	private RequestContext ctx;

	@Before
	public void setup() {
		Configuration configuration = TestHelper.buildConfiguration(new HashMap<String, String>() {{
			put(Constants.PROP_HOME, "url");
		}});

		ctx = new RequestContext(req, res, idpMetadata, spMetadata, credential, configuration, handler, bindingHandlerFactory);
	}

	@Test
	public void sendResponse_should_redirect_to_requestURI() throws Exception {
		String uri = "/test/something/";
		Request r = new Request(uri, null, "GET", new HashMap<String, String[]>());
		
		context.checking(new Expectations() {{
			one(res).sendRedirect("/test/something/");
		}});
		setCachingHeaders();
		
		HTTPUtils.sendResponse(r, ctx);
	}

	@Test
	public void sendResponse_should_strip_multiple_slashes() throws Exception {
		String uri = "//test/something/";
		Request r = new Request(uri, null, "GET", new HashMap<String, String[]>());
		
		context.checking(new Expectations() {{
			one(res).sendRedirect("/test/something/");
		}});
		setCachingHeaders();
		
		HTTPUtils.sendResponse(r, ctx);
		
	}
	
	private void setCachingHeaders() {
		context.checking(new Expectations() {{
			allowing(res).addHeader(with(any(String.class)), with(any(String.class)));
			allowing(res).addDateHeader(with(any(String.class)), with(any(long.class)));
			one(req).getCookies();
		}});
	}
}
