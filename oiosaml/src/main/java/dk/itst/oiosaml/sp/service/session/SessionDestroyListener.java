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

import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;

import dk.itst.oiosaml.logging.Audit;
import dk.itst.oiosaml.logging.Logger;
import dk.itst.oiosaml.logging.LoggerFactory;
import dk.itst.oiosaml.logging.Operation;
import dk.itst.oiosaml.sp.model.OIOAssertion;

/**
 * Listener for cleaning up when sessions are destroyed by the container.
 * @author recht
 *
 */
public class SessionDestroyListener implements HttpSessionListener {
	private static final Logger logger = LoggerFactory.getLogger(SessionDestroyListener.class);

	public void sessionCreated(HttpSessionEvent arg0) {
		logger.debug("Session: " + arg0);
	}

	/**
	 * If the user is logged in, remove the assertion from the sessionhandler.
	 */
	public void sessionDestroyed(HttpSessionEvent e) {
		SessionHandlerFactory sf = SessionHandlerFactory.Factory.newInstance(null);
		if (sf == null) {
			logger.warn("No SessionHandler configured, skipping session destroy");
			return;
		}
		if (e.getSession() == null) return;
		
		SessionHandler handler = sf.getHandler();
		boolean loggedIn = handler.isLoggedIn(e.getSession().getId());
		logger.debug("User logged in: " + loggedIn);
		if (loggedIn) {
			OIOAssertion assertion = handler.getAssertion(e.getSession().getId());
			Audit.logSystem(e.getSession().getId(), assertion.getID(), Operation.TIMEOUT, assertion.getSubjectNameIDValue());
			
			handler.logOut(e.getSession().getId());
		} else {
			logger.debug("Session destroyed without saml assertion");
		}
		
	}
}
