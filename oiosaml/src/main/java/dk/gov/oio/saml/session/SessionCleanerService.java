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

import dk.gov.oio.saml.config.Configuration;
import dk.gov.oio.saml.service.OIOSAML3Service;
import dk.gov.oio.saml.util.InternalException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.http.HttpSession;
import java.util.Timer;
import java.util.TimerTask;

public class SessionCleanerService {
    private static final Logger log = LoggerFactory.getLogger(SessionCleanerService.class);

    private boolean initialized = false;
    private Timer cleanupTimer;

    public SessionCleanerService(Configuration configuration) {
    }

    public synchronized void updateCleaner(HttpSession session) {
        try {
            if (!initialized) {
                startCleaner(0 != session.getMaxInactiveInterval() ?
                        (long)session.getMaxInactiveInterval() * 1000L :
                        30L * 60L * 1000L /* default */);

                initialized = true;
            }
        } catch (Exception e) {
            log.error("Unable to start session cleaner", e);
        }
    }

    public void startCleaner(final long maxInactiveInterval) {
        log.info("Starting session cleaner with timeout '{}'", maxInactiveInterval);
        if (cleanupTimer != null) {
            cleanupTimer.cancel();
        }

        cleanupTimer = new Timer("Session Cleanup");

        cleanupTimer.schedule(new TimerTask() {
            public void run() {
                log.debug("Cleaning session data, time: {}, timeout: {}", System.currentTimeMillis(), maxInactiveInterval);
                try {
                    SessionHandler sessionHandler = OIOSAML3Service.getSessionHandlerFactory().getHandler();
                    sessionHandler.cleanup(maxInactiveInterval);
                } catch (Exception e) {
                    log.error("Failed removing old session data", e);
                }
            }
        }, 0, maxInactiveInterval);
    }

    public void stopCleaner() {
        if (cleanupTimer != null) {
            cleanupTimer.cancel();
            cleanupTimer = null;
        }
    }
}
