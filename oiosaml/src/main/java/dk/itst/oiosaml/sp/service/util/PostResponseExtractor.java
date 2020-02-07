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
package dk.itst.oiosaml.sp.service.util;

import java.io.UnsupportedEncodingException;

import javax.servlet.http.HttpServletRequest;

import dk.itst.oiosaml.logging.Logger;
import dk.itst.oiosaml.logging.LoggerFactory;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.util.Base64;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.error.Layer;
import dk.itst.oiosaml.error.WrappedException;
import dk.itst.oiosaml.sp.model.OIOResponse;

/**
 * Class for extracting a SAML Response from a POST parameter.
 * 
 * @author Joakim Recht <jre@trifork.com>
 *
 */
public class PostResponseExtractor {
	private static final Logger log = LoggerFactory.getLogger(PostResponseExtractor.class);
	
	public OIOResponse extract(HttpServletRequest request) {
		String samlResponse = request.getParameter(Constants.SAML_SAMLRESPONSE);
		if (samlResponse == null) {
			throw new IllegalStateException("SAMLResponse parameter cannot be null");
		}
		if (log.isDebugEnabled()) log.debug("SAMLResponse: " + samlResponse);
		
		try {
			String xml = new String(Base64.decode(samlResponse), "UTF-8");
			XMLObject obj = SAMLUtil.unmarshallElementFromString(xml);
			if (!(obj instanceof Response)) {
				throw new IllegalArgumentException("SAMLResponse must be of type Response. Was " + obj);
			}
			return new OIOResponse((Response) obj);
		} catch (UnsupportedEncodingException e) {
			throw new WrappedException(Layer.BUSINESS, e);
		}
	}

}
