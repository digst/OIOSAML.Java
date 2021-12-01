package dk.gov.oio.saml.audit;

import java.util.EventListener;

public interface AuditAdapter {
    /**
     * Audit log a message, e.g. AuthnRequest or Assertion from SAML
     */
    void auditLog(String message);
}