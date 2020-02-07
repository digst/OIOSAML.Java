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

import org.opensaml.xml.security.credential.Credential;

import dk.itst.oiosaml.sp.model.OIOAuthnRequest;

/**
 * Handle AuthnRequest generation for a protoocl binding.
 * 
 * Each protocol binding is implemented by a {@link BindingHandler}, which is responsible for
 * generating a {@link OIOAuthnRequest} and transmit it using the implemented binding.
 * 
 * @author Joakim Recht <jre@trifork.com>
 * @author Rolf Njor Jensen <rolf@trifork.com>
 *
 */
public interface BindingHandler {
	
	/**
	 * Get the SAML uri for the protocol binding.
	 */
	public String getBindingURI();

	public void handle(HttpServletRequest req, HttpServletResponse response, Credential credential, OIOAuthnRequest authnRequest) throws IOException, ServletException;
}
