package dk.gov.oio.saml.session;

import dk.gov.oio.saml.config.Configuration;
import dk.gov.oio.saml.service.OIOSAML3Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
                long maxInactiveIntervalSeconds = session.getMaxInactiveInterval() > 0 ?
                        (long)session.getMaxInactiveInterval() :
                        30L * 60L /* defaults to 30 minutes */;

                initializeCleaner(maxInactiveIntervalSeconds);

                initialized = true;
            }
        } catch (Exception e) {
            log.error("Unable to start session cleaner", e);
        }
    }

    private void initializeCleaner(final long maxInactiveIntervalSeconds) {
        log.info("Starting session cleaner with timeout '{}'", maxInactiveIntervalSeconds);
        if (cleanupTimer != null) {
            stopCleaner();
        }

        cleanupTimer = new Timer("Session Cleanup");

        cleanupTimer.schedule(new TimerTask() {
            public void run() {
                log.debug("Cleaning session data, time: {}, timeout: {}", System.currentTimeMillis(), maxInactiveIntervalSeconds * 1000);
                try {
                    SessionHandler sessionHandler = OIOSAML3Service.getSessionHandlerFactory().getHandler();
                    sessionHandler.cleanup(maxInactiveIntervalSeconds);
                } catch (Exception e) {
                    log.error("Failed removing old session data", e);
                }
            }
        }, 0, maxInactiveIntervalSeconds * 1000);
    }

    public synchronized void stopCleaner() {
        if (cleanupTimer != null) {
            cleanupTimer.cancel();
            cleanupTimer = null;
        }
    }
}
