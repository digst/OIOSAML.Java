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
package dk.gov.oio.saml.session;

import dk.gov.oio.saml.audit.AuditService;
import dk.gov.oio.saml.service.OIOSAML3Service;
import dk.gov.oio.saml.util.AuditRequestUtil;
import dk.gov.oio.saml.util.InternalException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;


/**
 * Listener for cleaning up when sessions are destroyed by the container.
 * @author recht
 *
 */
public class SessionDestroyListener implements HttpSessionListener {
    private static final Logger log = LoggerFactory.getLogger(SessionDestroyListener.class);

    public void sessionCreated(HttpSessionEvent httpSessionEvent) {
        log.debug("Session: {}", httpSessionEvent);
    }

    /**
     * If the user is logged in, remove the assertion from the sessionhandler.
     */
    public void sessionDestroyed(HttpSessionEvent httpSessionEvent) {
        if (null == httpSessionEvent.getSession()) {
            log.debug("No session exists in current context");
            return;
        }
        try {
            SessionHandler handler = OIOSAML3Service.getSessionHandlerFactory().getHandler();
            boolean loggedIn = handler.isAuthenticated(httpSessionEvent.getSession());
            String sessionId = handler.getSessionId(httpSessionEvent.getSession());
            log.debug("User on session {} logged in: {}", sessionId, loggedIn);

            if (loggedIn) {
                AssertionWrapper assertion = handler.getAssertion(httpSessionEvent.getSession());

                OIOSAML3Service.getAuditService().auditLog(new AuditService
                                .Builder()
                                .withAuthnAttribute("ACTION", "TIMEOUT")
                                .withAuthnAttribute("DESCRIPTION", "SessionDestroyed")
                                .withAuthnAttribute("SP_SESSION_ID", sessionId)
                                .withAuthnAttribute("ASSERTION_ID", assertion.getID())
                                .withAuthnAttribute("SUBJECT_NAME_ID", assertion.getSubjectNameId()));

                handler.logout(httpSessionEvent.getSession(), assertion);
            } else {
                log.debug("Session destroyed without saml assertion");
            }
        } catch (InternalException ex) {
            log.error("Error trying to logout http session {}", httpSessionEvent.getSession().getId(), ex);
        }
    }
}
