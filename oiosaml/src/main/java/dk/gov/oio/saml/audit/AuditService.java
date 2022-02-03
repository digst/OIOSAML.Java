package dk.gov.oio.saml.audit;

import dk.gov.oio.saml.config.Configuration;
import dk.gov.oio.saml.util.StringUtil;
import org.opensaml.core.config.InitializationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.LinkedHashMap;
import java.util.Map;

public class AuditService {
    private static final Logger log = LoggerFactory.getLogger(AuditService.class);
    private static SimpleDateFormat JSON_DATE_FORMATTER = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");

    private transient AuditLogger auditLogger;
    private transient Configuration configuration;

    public AuditService(Configuration configuration) throws InitializationException {
        log.debug("Initialize AuditService");
        this.configuration = configuration;
        this.auditLogger = createAuditLogger(configuration.getAuditLoggerClassName());
    }

    /**
     * Audit log a message, e.g. AuthnRequest or Assertion from SAML
     * @param auditBuilder audit log statement
     */
    public void auditLog(Builder auditBuilder) {
        if (null != auditBuilder) {
            auditLogger.auditLog(auditBuilder
                    .withAuthnAttribute("Time", JSON_DATE_FORMATTER.format(Calendar.getInstance().getTime()))
                    .withAuthnAttribute("SpEntityID", configuration.getSpEntityID())
                    .withAuthnAttribute("IdpEntityID", configuration.getIdpEntityID())
                    .toJSON());
        }
    }

    public static class Builder {
        private Map<String,String> auditMap = new LinkedHashMap<>();

        public Builder withAuthnAttribute(String key, String value) {
            auditMap.putIfAbsent(key, value);
            return this;
        }

        public String toJSON() {
            return StringUtil.map2json(auditMap);
        }
    }

    private AuditLogger createAuditLogger(String auditLoggerClassName) throws InitializationException {
        Class<?> adapterClazz = Slf4JAuditLogger.class;
        try {
            if (StringUtil.isNotEmpty(auditLoggerClassName)) {
                log.info("Initializing AuditLogger '{}'", auditLoggerClassName);
                adapterClazz = Class.forName(auditLoggerClassName);
            }

            for (Constructor<?> constructor : adapterClazz.getConstructors()) {
                if (constructor.getParameterTypes().length == 0) {

                    log.info("Create '{}' AuditLogger", adapterClazz.getName());
                    return (AuditLogger) constructor.newInstance();
                }
            }
            throw new InitializationException(String.format("Cannot create AuditLogger, '%s' must have default constructor", adapterClazz.getName()));

        } catch (ClassNotFoundException | ClassCastException | InstantiationException | IllegalAccessException | InvocationTargetException e) {
            log.error("Failed creating AuditLogger", e);
            throw new InitializationException(String.format("Cannot create AuditLogger, '%s' must have default constructor and implement 'dk.gov.oio.saml.audit.AuditLogger'", adapterClazz.getName()), e);
        }
    }
}
