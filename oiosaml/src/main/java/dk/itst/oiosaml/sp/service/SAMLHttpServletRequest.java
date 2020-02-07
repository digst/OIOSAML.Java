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

import java.security.Principal;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import dk.itst.oiosaml.sp.OIOPrincipal;
import dk.itst.oiosaml.sp.UserAssertion;
import dk.itst.oiosaml.sp.service.util.Constants;

public class SAMLHttpServletRequest extends HttpServletRequestWrapper {

	private final UserAssertion assertion;
	private final String hostname;
	private String relayState;

	public SAMLHttpServletRequest(HttpServletRequest request, UserAssertion assertion, String hostname) {
		super(request);
		this.assertion = assertion;
		this.hostname = hostname;
	}

	public SAMLHttpServletRequest(HttpServletRequest servletRequest, String hostname, String relayState) {
		this(servletRequest, (UserAssertion)null, hostname);
		this.relayState = relayState;
	}

	@Override
	public String getRemoteUser() {
		if (assertion != null) {
			return assertion.getSubject();
		}
		
		return super.getRemoteUser();
	}
	
	@Override
	public Principal getUserPrincipal() {
		if (assertion != null) {
			return new OIOPrincipal(assertion);
		}
		
		return super.getUserPrincipal();
	}
	
	@Override
	public StringBuffer getRequestURL() {
		String url = super.getRequestURL().toString();
		
		String mod = hostname + url.substring(url.indexOf('/', 8));
		return new StringBuffer(mod);
	}

	@Override
	public String getParameter(String name) {
		if (Constants.SAML_RELAYSTATE.equals(name) && relayState != null) {
			return relayState;
		}
		return super.getParameter(name);
	}
	
	@Override
	public String getQueryString() {
		if (relayState == null) return super.getQueryString();
		
		String q = super.getQueryString();
		if (q == null) {
			q = "";
		}
		return new StringBuilder(q).append("&").append(Constants.SAML_RELAYSTATE).append("=").append(relayState).toString();
	}
}
