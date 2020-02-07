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
package dk.itst.oiosaml.sp.service.session;

import dk.itst.oiosaml.sp.service.util.Constants;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

public class Request implements Serializable {
	private static final long serialVersionUID = 8582710873277995206L;
	private final String requestURI;
	private final String queryString;
	private final String method;
	private final Map<String, String[]> parameters;

	public Request(String requestURI, String queryString, String method, Map<String, String[]> parameters) {
		this.requestURI = requestURI;

        // Remove forceAuthn attribute if it was part of request. This is done in order to avoid an infinite loop of force logins.
        this.queryString = queryString == null ? null : queryString.replaceAll(Constants.QUERY_STRING_FORCE_AUTHN + "=.*?($|[&;])", "");

        this.method = method;

        // Remove forceAuthn attribute if it was part of POST request. This is done in order to avoid an infinite loop of force logins.
        if(parameters != null)
            parameters.remove(Constants.QUERY_STRING_FORCE_AUTHN);
		this.parameters = parameters;
	}
	
	@SuppressWarnings("unchecked")
	public static Request fromHttpRequest(HttpServletRequest req) {
        // req.getParameterMap() is a weak reference and is cleared between requests. req.getParameterMap() is only used in combination with POST logins and properly redirection after login was not possible without the parameter map.
        Map<String, String[]> copy = new HashMap<String, String[]>();
        copy.putAll(req.getParameterMap());
        return new Request(req.getRequestURI(), req.getQueryString(), req.getMethod(), copy);
	}
	

	public String getMethod() {
		return method;
	}
	
	public Map<String, String[]> getParameters() {
		return parameters;
	}
	
	public String getQueryString() {
		return queryString;
	}
	
	public String getRequestURI() {
		return requestURI;
	}
}
