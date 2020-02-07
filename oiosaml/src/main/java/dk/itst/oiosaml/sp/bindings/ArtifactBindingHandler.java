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

/**
 * Handler for generating AuthnRequest with Artifact binding.
 * 
 * This handler can generate a new AuthnRequest using the http redirect method.
 * 
 * @author Joakim Recht <jre@trifork.com>
 *
 */
public class ArtifactBindingHandler implements BindingHandler {
	private final static Logger log = LoggerFactory.getLogger(ArtifactBindingHandler.class);
	public static final String VERSION = "$Id: ClientSSOEngine.java 2546 2008-04-11 13:29:25Z jre $";

	public String getBindingURI() {
		return SAMLConstants.SAML2_ARTIFACT_BINDING_URI;
	}

	public void handle(HttpServletRequest req, HttpServletResponse response, Credential credential, OIOAuthnRequest authnRequest) throws IOException, ServletException {
		String requestURI = authnRequest.getRedirectURL(credential);
		
		if (log.isDebugEnabled())
			log.debug("redirectURL...:" + requestURI);
		Audit.log(Operation.AUTHNREQUEST_REDIRECT_ARTIFACT, true, authnRequest.getID(), requestURI);
		
		response.sendRedirect(requestURI);
	}
	
}
