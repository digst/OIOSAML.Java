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
package dk.itst.oiosaml.sp.bindings;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import dk.itst.oiosaml.logging.Logger;
import dk.itst.oiosaml.logging.LoggerFactory;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.xml.security.credential.Credential;

import dk.itst.oiosaml.logging.Audit;
import dk.itst.oiosaml.logging.Operation;
import dk.itst.oiosaml.sp.model.OIOAuthnRequest;
import dk.itst.oiosaml.sp.service.util.HTTPUtils;

public class RedirectBindingHandler implements BindingHandler {
	private static final Logger log = LoggerFactory.getLogger(RedirectBindingHandler.class);
	

	public String getBindingURI() {
		return SAMLConstants.SAML2_REDIRECT_BINDING_URI;
	}

	public void handle(HttpServletRequest req, HttpServletResponse response, Credential credential, OIOAuthnRequest authnRequest) throws IOException, ServletException {
		String url = authnRequest.getRedirectURL(credential);
		log.debug("Issuing redirect to " + url);
		
		Audit.log(Operation.AUTHNREQUEST_REDIRECT, true, authnRequest.getID(), url);
		HTTPUtils.sendMetaRedirect(response, url, null, HTTPUtils.getFragmentCookie(req) == null);
	}

}
