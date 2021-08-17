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
 *
 */

package dk.itst.oiosaml.discovery.service;

import java.io.IOException;
import java.util.Arrays;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

public class DiscoveryServlet extends AbstractServlet {
	private static final Logger log = Logger.getLogger(DiscoveryServlet.class);
	
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		log.info("Discovery request from " + req.getRemoteAddr() + ", referer: " + req.getParameter(REFERER_PARAMETER));
		
		if (req.getParameter(REFERER_PARAMETER) == null) {
			resp.sendError(HttpServletResponse.SC_PRECONDITION_FAILED, "The request must include a Referer (r) parameter. Unable to proceed");
			return;
		}
		
		Cookie[] cookies = req.getCookies();
		log.debug("Cookies for request: " + Arrays.toString(cookies));
		Cookie samlIdpCookie = findCookie(cookies);
		if (samlIdpCookie == null) {
			log.info("No saml idp cookie found, redirecting with empty parameter");
			sendRedirect(req.getParameter(REFERER_PARAMETER), "", resp);
		} else {
			sendRedirect(req.getParameter(REFERER_PARAMETER), Base64.encodeBytes(samlIdpCookie.getValue().getBytes()), resp);
		}
	}
	
	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		doGet(req, resp);
	}
}
