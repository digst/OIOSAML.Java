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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;

/**
 * Listener implemented to handle SameSite=Lax or similar settings on the
 * session cookie, when getting a cross-origin response from the SAML Identity Provider
 */
public class SessionCopyListener implements HttpSessionListener, SameSiteSessionSynchronizer {
	private static Map<String, HttpSession> sessions = new HashMap<String, HttpSession>();
	private static Map<String, String> sessionLinks = new HashMap<String, String>();
	
	public void sessionCreated(HttpSessionEvent event) {
		add(event.getSession());
	}

	public void sessionDestroyed(HttpSessionEvent event) {
		remove(event.getSession());
	}
	
	public HttpSession getSession(String requestId) {
		String sessionId = sessionLinks.get(requestId);
		if (sessionId != null) {
			HttpSession session = sessions.get(sessionId);

			if (session != null) { 
				return session;
			}
		}
		
		return null;
	}
	
	public synchronized void linkSession(String requestId, String sessionId) {
		sessionLinks.put(requestId, sessionId);
	}
	
	private static synchronized void add(HttpSession session) {
		sessions.put(session.getId(), session);
	}
	
	private static synchronized void remove(HttpSession session) {
		sessions.remove(session.getId());
		
		List<String> toRemove = new ArrayList<String>();

		// cleanup session links as well
		for (String key : sessionLinks.keySet()) {
			if (sessionLinks.get(key).equals(session.getId())) {
				toRemove.add(key);
				return;
			}
		}
		
		for (String key : toRemove) {
			sessionLinks.remove(key);
		}
	}
}
