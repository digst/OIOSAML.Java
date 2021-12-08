package dk.gov.oio.saml.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

/**
 * SLF4J default audit logging adapter.
 *
 * NB: This log need to be persisted 6 months, so implementing a JPA based adapter and serializing
 * this to a database seems a better choice than just appending to output.
 */
public class Slf4JAuditLogger implements AuditLogger {
    private static final Logger log = LoggerFactory.getLogger(Slf4JAuditLogger.class);
    private static Marker audit = MarkerFactory.getMarker("AUDIT");

    /**
     * SLF4J default audit logging adapter, audit logging must be persisted 6 month.
     */
    public Slf4JAuditLogger() {
        log.info("SLF4J default audit logging adapter created, audit logging must be persisted 6 month!");
    }

    /**
     * Audit log a message, e.g. AuthnRequest or Assertion from SAML
     *
     * @param message
     */
    @Override
    public void auditLog(String message) {
        // Separate this log from existing logging
        log.info(audit, "AUDIT: {}", message);
    }
}
