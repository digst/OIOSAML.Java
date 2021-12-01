package dk.gov.oio.saml.service;

import dk.gov.oio.saml.audit.AuditService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.xmlsec.config.impl.JavaCryptoValidationInitializer;

import dk.gov.oio.saml.config.Configuration;

public class OIOSAML3Service {
    private static final Logger log = LoggerFactory.getLogger(OIOSAML3Service.class);

    public static boolean initialized = false;
    private static Configuration configuration;
    private static AuditService auditService;

    public static void init(Configuration configuration) throws InitializationException {
        if (log.isDebugEnabled()) {
            log.debug("Initializing OIOSAML");
        }

        // Validate Crypto
        if (log.isDebugEnabled()) {
            log.debug("Validating Java Cryptographic Architecture");
        }
        JavaCryptoValidationInitializer cryptoValidationInitializer = new JavaCryptoValidationInitializer();
        cryptoValidationInitializer.init();

        // Initialize OpenSAML
        if (log.isDebugEnabled()) {
            log.debug("Initializing OpenSAML");
        }
        InitializationService.initialize();

        // Set configuration
        if (log.isDebugEnabled()) {
            log.debug("Setting OIOSAML Configuration");
        }
        OIOSAML3Service.configuration = configuration;
        OIOSAML3Service.auditService = new AuditService(configuration);
        initialized = true;

        if (log.isDebugEnabled()) {
            log.debug("OIOSAML Initialized");
        }
    }

    public static Configuration getConfig() throws RuntimeException {
        if (!initialized) {
            throw new RuntimeException("Configuration not set");
        }

        return configuration;
    }

    public static AuditService getAuditService() throws RuntimeException {
        if (!initialized) {
            throw new RuntimeException("Configuration not set");
        }

        return auditService;
    }
}
