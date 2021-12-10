package dk.gov.oio.saml.audit;

/**
 * Audit logging adapter interface used in OIOSAML configuration.
 * See Slf4JAuditLogger.
 */
public interface AuditLogger {
    /**
     * Audit log a message in JSON format, created with AuditService.Builder, e.g. AuthnRequest or Assertion from SAML.
     * @param message log message in JSON format, created with AuditService.Builder
     */
    void auditLog(String message);
}
