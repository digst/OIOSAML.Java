package dk.gov.oio.saml.service;

import dk.gov.oio.saml.audit.AuditService;
import dk.gov.oio.saml.session.InternalSessionHandlerFactory;
import dk.gov.oio.saml.session.SessionCleanerService;
import dk.gov.oio.saml.session.SessionHandlerFactory;
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

        try {
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
            OIOSAML3Service.sessionCleanerService = new SessionCleanerService(configuration);
            OIOSAML3Service.sessionHandlerFactory = new InternalSessionHandlerFactory();
            OIOSAML3Service.sessionHandlerFactory.configure(configuration);

            initialized = true;
        } catch (Exception exception) {
            log.error("Unable to initialize OIOSAML",exception);
            throw new InitializationException(String.format("Unable to initialize OIOSAML '%s'", exception.getMessage()), exception);
        }

        log.debug("OIOSAML Initialized");
    }

    public static Configuration getConfig() throws RuntimeException {
        ifNotInitializedThrowRuntimeException("Configuration");
        return configuration;
    }

    public static AuditService getAuditService() throws RuntimeException {
        ifNotInitializedThrowRuntimeException("AuditService");
        return auditService;
    }

    public static SessionHandlerFactory getSessionHandlerFactory() throws RuntimeException {
        ifNotInitializedThrowRuntimeException("SessionHandlerFactory");
        return sessionHandlerFactory;
    }

    public static SessionCleanerService getSessionCleanerService() {
        ifNotInitializedThrowRuntimeException("SessionCleanerService");
        return sessionCleanerService;
    }

    private static void ifNotInitializedThrowRuntimeException(String entity) {
        if (!initialized) {
            throw new RuntimeException(String.format("OIOSAML3 is uninitialized, '%s' is unavailable", entity));
        }
    }
}
