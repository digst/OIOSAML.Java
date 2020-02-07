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
package dk.itst.oiosaml.sp.service;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.text.StringStartsWith;
import org.jmock.Expectations;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.util.Base64;
import org.w3c.dom.Document;

import dk.itst.oiosaml.common.OIOSAMLConstants;
import dk.itst.oiosaml.sp.UserAssertionHolder;
import dk.itst.oiosaml.sp.UserAssertionImpl;
import dk.itst.oiosaml.sp.bindings.ArtifactBindingHandler;
import dk.itst.oiosaml.sp.bindings.BindingHandler;
import dk.itst.oiosaml.sp.bindings.BindingHandlerFactory;
import dk.itst.oiosaml.sp.metadata.IdpMetadata;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.model.OIOAuthnRequest;
import dk.itst.oiosaml.sp.service.util.Constants;
import dk.itst.oiosaml.sp.service.util.Utils;


public class LoginHandlerTest extends AbstractServiceTests {
	
	private BindingHandlerFactory handlerFactory;
	private LoginHandler lh;
	private Map<String, String> conf;

	@Before
	public void setUp() {
		handlerFactory = bindingHandlerFactory;
		
		lh = new LoginHandler();
		conf = new HashMap<String, String>();
		conf.put(Constants.PROP_SUPPORTED_BINDINGS, SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
		conf.put(Constants.PROP_PROTOCOL, SAMLConstants.SAML20P_NS);
		context.checking(new Expectations() {{
			allowing(req).getRequestURI(); will(returnValue("http://test"));
			allowing(req).getPathInfo(); will(returnValue("/test"));
			allowing(req).getRequestURL(); will(returnValue(new StringBuffer("http://test")));
			allowing(req).getQueryString();
			allowing(req).getParameter("RelayState"); will(returnValue(null));
			allowing(session).getAttribute(Constants.SESSION_USER_ASSERTION); will(returnValue(null));
		}});
	}
	
	@Test
	public void redirectToDiscoveryWhenNoSession() throws Exception {
		IdpMetadata md = getDiscoveryMetadata();
		conf.put(Constants.DISCOVERY_LOCATION, "http://discovery");
		
		final StringWriter sw = new StringWriter();
		context.checking(new Expectations() {{
			one(req).getParameter(Constants.DISCOVERY_ATTRIBUTE); will(returnValue(null));
			one(res).getWriter(); will(returnValue(new PrintWriter(sw)));
			one(res).setContentType("text/html");
			allowing(res).addHeader(with(any(String.class)), with(any(String.class)));
			allowing(res).addDateHeader(with(any(String.class)), with(any(Long.class)));
		}});
		lh.handleGet(getContext(md));
		
		assertTrue(sw.toString().contains("0;url=http://discovery?r=" + URLEncoder.encode("http://test", "UTF-8")));
	}

	@Test
	public void testUseDefaultIdPWhenNoSupportedIdpDiscovered() throws Exception {
		final String enc = Base64.encodeBytes("dummyidp".getBytes());
		final BindingHandler bHandler = new ArtifactBindingHandler(); //context.mock(BindingHandler.class);
		
		IdpMetadata md = getDiscoveryMetadata();
		final String expectedRedirectLocation = md.getFirstMetadata().getSingleSignonServiceLocation(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
		
		context.checking(new Expectations() {{
            allowing(req).getParameterMap();
			allowing(req).getParameter(Constants.DISCOVERY_ATTRIBUTE); will(returnValue(enc));
			one(handlerFactory).getBindingHandler(SAMLConstants.SAML2_ARTIFACT_BINDING_URI); will(returnValue(bHandler));
			one(session).removeAttribute(Constants.SESSION_USER_ASSERTION);
			one(res).sendRedirect(with(new StringStartsWith(expectedRedirectLocation)));
		}});
		lh.handleGet(getContext(md));
	}

	@Test
	public void testSelectDiscoveryIdp() throws Exception {
		final String enc = Base64.encodeBytes(idpMetadata.getFirstMetadata().getEntityID().getBytes());
		
		final BindingHandler bHandler = context.mock(BindingHandler.class);

		IdpMetadata md = getDiscoveryMetadata();
		conf.put(Constants.PROP_CERTIFICATE_LOCATION, "http://discovery");

		context.checking(new Expectations() {{
            allowing(req).getParameterMap();
			one(req).getParameter(Constants.DISCOVERY_ATTRIBUTE); will(returnValue(enc));
			one(handlerFactory).getBindingHandler(SAMLConstants.SAML2_ARTIFACT_BINDING_URI); will(returnValue(bHandler));
			allowing(bHandler).getBindingURI(); will(returnValue(SAMLConstants.SAML2_ARTIFACT_BINDING_URI));
			one(bHandler).handle(with(equal(req)), with(equal(res)), with(equal(credential)), with(any(OIOAuthnRequest.class)));
			one(session).removeAttribute(Constants.SESSION_USER_ASSERTION);
		}});
		lh.handleGet(getContext(md));
	}

	@Test
	public void testDefaultSelectedDiscoveryIdp() throws Exception {
		final BindingHandler bHandler = context.mock(BindingHandler.class);

		IdpMetadata md = getDiscoveryMetadata();
		conf.put(Constants.PROP_DISCOVERY_DEFAULT_IDP, "idp2");

		final StringValueHolder holder = new StringValueHolder();
		context.checking(new Expectations() {{
            allowing(req).getParameterMap();
			one(req).getParameter(Constants.DISCOVERY_ATTRIBUTE); will(returnValue(""));
			one(handlerFactory).getBindingHandler(SAMLConstants.SAML2_ARTIFACT_BINDING_URI); will(returnValue(bHandler));
			allowing(bHandler).getBindingURI(); will(returnValue(SAMLConstants.SAML2_ARTIFACT_BINDING_URI));
			one(bHandler).handle(with(equal(req)), with(equal(res)), with(equal(credential)), with(new BaseMatcher<OIOAuthnRequest>() {
				public boolean matches(Object item) {
					OIOAuthnRequest r = ((OIOAuthnRequest)item);
					holder.setValue(r.getID());
					return true;
				}
				public void describeTo(Description description) {}
			}));
			one(session).removeAttribute(Constants.SESSION_USER_ASSERTION);
		}});
		lh.handleGet(getContext(md));
		assertEquals("idp2", handler.removeEntityIdForRequest(holder.getValue()));
	}

	@Test
	public void testNameIDPolicy() throws Exception {
		final BindingHandler bHandler = new BindingHandler() {
			public String getBindingURI() {
				return SAMLConstants.SAML2_ARTIFACT_BINDING_URI;
			}

			public void handle(HttpServletRequest req, HttpServletResponse response, Credential credential, OIOAuthnRequest authnRequest) throws IOException, ServletException {
				String url = authnRequest.getRedirectURL(credential);
				try {
					Document doc = TestHelper.parseBase64Encoded(Utils.getParameter("SAMLRequest", url));
					AuthnRequest ar = (AuthnRequest) Configuration.getUnmarshallerFactory().getUnmarshaller(doc.getDocumentElement()).unmarshall(doc.getDocumentElement());
					
					assertNotNull(ar.getNameIDPolicy());
					assertTrue(ar.getNameIDPolicy().getAllowCreate());
					assertEquals(spMetadata.getEntityID(), ar.getNameIDPolicy().getSPNameQualifier());
					assertEquals(OIOSAMLConstants.PERSISTENT, ar.getNameIDPolicy().getFormat());
					
				} catch (Exception e) {
					throw new RuntimeException(e);
				}
				
			}
		};

		context.checking(new Expectations() {{
            allowing(req).getParameterMap();
			one(handlerFactory).getBindingHandler(SAMLConstants.SAML2_ARTIFACT_BINDING_URI); will(returnValue(bHandler));
			one(session).removeAttribute(Constants.SESSION_USER_ASSERTION);
		}});
		
		conf.put(Constants.PROP_NAMEID_POLICY, "persistent");
		conf.put(Constants.PROP_NAMEID_POLICY_ALLOW_CREATE, "true");

		lh.handleGet(getContext(idpMetadata));
	}

	@Test
	public void testForceAuthn() throws Exception {
		final BindingHandler bHandler = context.mock(BindingHandler.class);

		context.assertIsSatisfied();
		context.checking(new Expectations() {{
			one(handlerFactory).getBindingHandler(SAMLConstants.SAML2_ARTIFACT_BINDING_URI); will(returnValue(bHandler));
			allowing(bHandler).getBindingURI(); will(returnValue(SAMLConstants.SAML2_ARTIFACT_BINDING_URI));
			one(bHandler).handle(with(equal(req)), with(equal(res)), with(equal(credential)), with(new BaseMatcher<OIOAuthnRequest>() {
				public boolean matches(Object item) {
					OIOAuthnRequest r = ((OIOAuthnRequest)item);
					assertTrue(r.isForceAuthn());
					return true;
				}
				public void describeTo(Description description) {}
			}));
			one(session).removeAttribute(Constants.SESSION_USER_ASSERTION);
		}});
		
		conf.put(Constants.PROP_FORCE_AUTHN_URLS, "nothere, /te.*");
		lh.handleGet(getContext(idpMetadata));
	}
	
	@Test
	public void testPassive() throws Exception {
		final BindingHandler bHandler = context.mock(BindingHandler.class);

		context.assertIsSatisfied();
		context.checking(new Expectations() {{
            allowing(req).getParameterMap();
			one(handlerFactory).getBindingHandler(SAMLConstants.SAML2_ARTIFACT_BINDING_URI); will(returnValue(bHandler));
			allowing(bHandler).getBindingURI(); will(returnValue(SAMLConstants.SAML2_ARTIFACT_BINDING_URI));
			one(bHandler).handle(with(equal(req)), with(equal(res)), with(equal(credential)), with(new BaseMatcher<OIOAuthnRequest>() {
				public boolean matches(Object item) {
					OIOAuthnRequest r = ((OIOAuthnRequest)item);
					assertTrue(r.isPassive());
					return true;
				}
				public void describeTo(Description description) {}
			}));
			one(session).removeAttribute(Constants.SESSION_USER_ASSERTION);
		}});

		conf.put(Constants.PROP_PASSIVE, "true");
		lh.handleGet(getContext(idpMetadata));
	}
	
	@Test
	public void testLogin() throws Exception {
		final BindingHandler bHandler = context.mock(BindingHandler.class);

		final StringValueHolder holder = new StringValueHolder();
		UserAssertionHolder.set(new UserAssertionImpl(new OIOAssertion(assertion)));		
		context.assertIsSatisfied();
		context.checking(new Expectations() {{
            allowing(req).getParameterMap();
			one(handlerFactory).getBindingHandler(SAMLConstants.SAML2_ARTIFACT_BINDING_URI); will(returnValue(bHandler));
			allowing(bHandler).getBindingURI(); will(returnValue(SAMLConstants.SAML2_ARTIFACT_BINDING_URI));
			one(bHandler).handle(with(equal(req)), with(equal(res)), with(equal(credential)), with(new BaseMatcher<OIOAuthnRequest>() {
				public boolean matches(Object item) {
					OIOAuthnRequest r = ((OIOAuthnRequest)item);
					holder.setValue(r.getID());
					assertFalse(r.isForceAuthn());
					assertFalse(r.isPassive());
					return true;
				}
				public void describeTo(Description description) {}
			}));
			one(session).removeAttribute(Constants.SESSION_USER_ASSERTION);
		}});
		lh.handleGet(getContext(idpMetadata));
		assertNull(UserAssertionHolder.get());
		assertEquals(idpEntityId, handler.removeEntityIdForRequest(holder.getValue()));
	}

	private IdpMetadata getDiscoveryMetadata() {
		EntityDescriptor ed1 = TestHelper.buildEntityDescriptor(credential);
		EntityDescriptor ed2 = TestHelper.buildEntityDescriptor(credential);
		ed2.setEntityID("idp2");
		IdpMetadata md = new IdpMetadata(SAMLConstants.SAML20P_NS, ed1, ed2);
		return md;
	}

	private RequestContext getContext(IdpMetadata md) {
		return new RequestContext(req, res, md, spMetadata, credential, TestHelper.buildConfiguration(conf), handler, handlerFactory);		
	}

}
