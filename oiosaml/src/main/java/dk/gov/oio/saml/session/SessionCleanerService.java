package dk.gov.oio.saml.session;

import dk.gov.oio.saml.config.Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpSession;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * The purpose for SessionCleanerService is removing OIOSAML sessions that has timed out,
 * but have not been removed by the SessionDestroyListener.
 * SessionCleanerService runs with a regular interval defined by the server session timeout.
 * SessionCleanerService is initialized in the OIOSAML3Service.
 */
public class SessionCleanerService {
    private static final Logger log = LoggerFactory.getLogger(SessionCleanerService.class);

    private ScheduledExecutorService scheduledThreadPool;
    private boolean initialized = false;

    public SessionCleanerService(Configuration configuration) {
    }

    /**
     * startCleanerIfMissing starts the cleanup task, if it is not already running.
     * SessionCleanerService needs a running session to access MaxInactiveInterval.
     * @param session
     */
    public void startCleanerIfMissing(HttpSession session) {
        if (!initialized) {
            initializeCleanerService(session);
        }
    }

    private synchronized void initializeCleanerService(HttpSession session) {
        if (initialized) {
            // Exit if already initialized
            return;
        }

        // Get session timeout from the session
        long maxInactiveIntervalSeconds = session.getMaxInactiveInterval() > 0 ?
                (long) session.getMaxInactiveInterval() :
                30L * 60L /* defaults to 30 minutes */;

        try {
            log.info("Starting session cleaner with timeout '{}'", maxInactiveIntervalSeconds);

            scheduledThreadPool = Executors.newScheduledThreadPool(1);

            scheduledThreadPool.scheduleWithFixedDelay(
                    new SessionCleanerTask(maxInactiveIntervalSeconds), 0, maxInactiveIntervalSeconds, TimeUnit.SECONDS);

            initialized = true;
        } catch (Exception e) {
            log.warn("Unable to start session cleaner", e);
        }
    }

    public synchronized void stopCleaner() {
        if (scheduledThreadPool != null) {
            scheduledThreadPool.shutdown();
        }
        scheduledThreadPool = null;
        initialized = false;
    }
}
