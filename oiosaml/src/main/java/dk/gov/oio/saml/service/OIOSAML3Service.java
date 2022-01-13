package dk.gov.oio.saml.service;

import dk.gov.oio.saml.audit.AuditService;
import dk.gov.oio.saml.session.InternalSessionHandlerFactory;
import dk.gov.oio.saml.session.SessionCleanerService;
import dk.gov.oio.saml.session.SessionHandlerFactory;
import dk.gov.oio.saml.util.InternalException;
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
    private static SessionHandlerFactory sessionHandlerFactory;
    private static SessionCleanerService sessionCleanerService;

    public static void init(Configuration configuration) throws InitializationException {
        log.debug("Initializing OIOSAML");

        // Validate Crypto
        log.debug("Validating Java Cryptographic Architecture");
        JavaCryptoValidationInitializer cryptoValidationInitializer = new JavaCryptoValidationInitializer();
        cryptoValidationInitializer.init();

        // Initialize OpenSAML
        log.debug("Initializing OpenSAML");
        InitializationService.initialize();

        // Set configuration
        log.debug("Setting OIOSAML Configuration");
        OIOSAML3Service.configuration = configuration;
        OIOSAML3Service.auditService = new AuditService(configuration);
        OIOSAML3Service.sessionHandlerFactory = new InternalSessionHandlerFactory();
        OIOSAML3Service.sessionHandlerFactory.configure(configuration);
        OIOSAML3Service.sessionCleanerService = new SessionCleanerService(configuration);

        initialized = true;

        log.debug("OIOSAML Initialized");
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

    public static SessionHandlerFactory getSessionHandlerFactory() throws RuntimeException {
        if (!initialized) {
            throw new RuntimeException("Configuration not set");
        }
        return sessionHandlerFactory;
    }

    public static SessionCleanerService getSessionCleanerService() {
        if (!initialized) {
            throw new RuntimeException("Configuration not set");
        }
        return sessionCleanerService;
    }
}
