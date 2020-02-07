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

import java.util.HashMap;
import java.util.Map;

import org.opensaml.common.xml.SAMLConstants;

public class DefaultBindingHandlerFactory implements BindingHandlerFactory {
	private final static Map<String, BindingHandler> handlers = new HashMap<String, BindingHandler>() {
		private static final long serialVersionUID = 469249093583103484L;
		{
			put(SAMLConstants.SAML2_ARTIFACT_BINDING_URI, new ArtifactBindingHandler());
			put(SAMLConstants.SAML2_POST_BINDING_URI, new PostBindingHandler());
			put(SAMLConstants.SAML2_REDIRECT_BINDING_URI, new RedirectBindingHandler());
		}
	};

	public BindingHandler getBindingHandler(String bindingName) throws IllegalArgumentException {
		BindingHandler handler = handlers.get(bindingName);
		if (handler == null) {
			throw new IllegalArgumentException(bindingName);
		}

		return handler;
	}
}
