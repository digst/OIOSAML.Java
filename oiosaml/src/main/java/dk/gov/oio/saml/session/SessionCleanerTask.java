package dk.gov.oio.saml.session;

import dk.gov.oio.saml.service.OIOSAML3Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * SessionCleanerTask is executed by the SessionCleanerService.
 * The purpose for SessionCleanerTask is removing OIOSAML sessions that has timed out,
 * but have not been removed by the SessionDestroyListener. *
 */
public class SessionCleanerTask implements Runnable {
    private static final Logger log = LoggerFactory.getLogger(SessionCleanerTask.class);

    private long maxInactiveIntervalSeconds;

    public SessionCleanerTask(long maxInactiveIntervalSeconds) {
        this.maxInactiveIntervalSeconds = maxInactiveIntervalSeconds;
    }

    @Override
    public void run() {
        log.debug("Cleaning session data, time: {}, timeout: {}", System.currentTimeMillis(), maxInactiveIntervalSeconds * 1000);
        try {
            SessionHandler sessionHandler = OIOSAML3Service.getSessionHandlerFactory().getHandler();
            sessionHandler.cleanup(maxInactiveIntervalSeconds);
        } catch (Exception e) {
            log.error("Failed removing old session data", e);
        }
    }
}
