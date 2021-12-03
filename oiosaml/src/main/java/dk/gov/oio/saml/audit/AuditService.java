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
import java.util.stream.Collectors;

public class AuditService {
    private static final Logger log = LoggerFactory.getLogger(AuditService.class);
    private static SimpleDateFormat JSON_DATE_FORMATTER = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");

    private transient AuditAdapter auditAdapter;
    private transient Configuration configuration;

    public AuditService(Configuration configuration) throws InitializationException {
        log.debug("Initialize AuditService");
        this.configuration = configuration;
        this.auditAdapter = createAuditAdapter(configuration.getAuditAdapterClassName());
    }

    /**
     * Audit log a message, e.g. AuthnRequest or Assertion from SAML
     */
    public void auditLog(Builder auditBuilder) {
        if (null != auditBuilder) {
            auditAdapter.auditLog(auditBuilder
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
            return auditMap
                    .entrySet()
                    .stream()
                    .map(entry -> String.format("\"%s\":\"%s\"", entry.getKey(), StringUtil.jsonEscape(entry.getValue())))
                    .collect(Collectors
                            .joining(",", "{", "}"));
        }
    }

    private AuditAdapter createAuditAdapter(String auditAdapterClassName) throws InitializationException {
        Class<?> adapterClazz = Slf4jAuditAdapter.class;
        try {
            if (null != auditAdapterClassName && auditAdapterClassName.length() > 0) {

                log.info(String.format("Initializing AuditAdapter '%s'", auditAdapterClassName));
                adapterClazz = Class.forName(auditAdapterClassName);
            }

            for (Constructor<?> constructor : adapterClazz.getConstructors()) {
                if (constructor.getParameterTypes().length == 0) {

                    log.info(String.format("Create '%s' AuditAdapter", adapterClazz.getName()));
                    return (AuditAdapter) constructor.newInstance();
                }
            }
            throw new InitializationException(String.format("Cannot create AuditAdapter, '%s' must have default constructor", adapterClazz.getName()));

        } catch (ClassNotFoundException | ClassCastException | InstantiationException | IllegalAccessException | InvocationTargetException e) {
            log.error("Failed creating AuditAdapter", e);
            throw new InitializationException(String.format("Cannot create AuditAdapter, '%s' must have default constructor and implement 'dk.gov.oio.saml.audit.AuditAdapter", adapterClazz.getName()), e);
        }
    }
}
