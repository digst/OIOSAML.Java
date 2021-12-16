package dk.gov.oio.saml.session;

import dk.gov.oio.saml.config.Configuration;
import dk.gov.oio.saml.session.inmemory.InMemorySessionHandlerFactory;
import dk.gov.oio.saml.util.InternalException;
import dk.gov.oio.saml.util.StringUtil;
import org.opensaml.core.config.InitializationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

public class InternalSessionHandlerFactory implements SessionHandlerFactory {
    private static final Logger log = LoggerFactory.getLogger(InternalSessionHandlerFactory.class);

    public InternalSessionHandlerFactory() {
    }

    private SessionHandlerFactory instance;

    /**
     * Close the factory. No calls to {@link #getHandler()} will be made after this call.
     * <p>
     * Be aware that this method might be called several times, and should not fail if this happens.
     */
    @Override
    public void close() {
        try {
            if (null != instance) {
                log.debug("Closing SessionHandlerFactory");
                instance.close();
            }
        } catch (Exception e) {
            log.warn("Failed closing SessionHandlerFactory: {}", e.getMessage());
        } finally {
            instance = null;
        }
    }

    /**
     * Get a new session handler.
     *
     * @return session handler instance
     */
    @Override
    public SessionHandler getHandler() throws InternalException {
        if (instance == null) {
            throw new InternalException("SessionHandlerFactory is uninitialized, configuration is missing");
        }
        return instance.getHandler();
    }

    /**
     * Configure the factory. This will be called before any calls are made to {@link #getHandler()}.
     *
     * @param config OIOSAML configuration
     */
    @Override
    public synchronized void configure(Configuration config) throws InitializationException {
        log.debug("Configure session handler factory: '{}'", config);

        if (null != instance) {
            log.warn("Session handler factory already configured");
            return;
        }

        if (null == config) {
            throw new InitializationException("Cannot create SessionHandlerFactory, missing configuration");
        }

        Class<?> clazz = InMemorySessionHandlerFactory.class;
        try {
            String name = config.getSessionHandlerFactoryClassName();
            if (StringUtil.isNotEmpty(name)) {
                log.info("Initializing SessionHandlerFactory '{}'", name);
                clazz = Class.forName(name);
            }

            for (Constructor<?> constructor : clazz.getConstructors()) {
                if (constructor.getParameterTypes().length == 0) {

                    log.info("Create '{}' SessionHandlerFactory", clazz.getName());
                    SessionHandlerFactory sessionHandlerFactory = (SessionHandlerFactory) constructor.newInstance();
                    sessionHandlerFactory.configure(config);

                    instance = sessionHandlerFactory;
                    return;
                }
            }

            log.error("Failed creating SessionHandlerFactory");
            throw new InitializationException(String.format("Cannot create SessionHandlerFactory, '%s' must have default constructor", clazz.getName()));

        } catch (ClassNotFoundException | ClassCastException | InstantiationException | IllegalAccessException | InvocationTargetException e) {
            log.error("Failed creating SessionHandlerFactory", e);
            throw new InitializationException(String.format("Cannot create SessionHandlerFactory, '%s' must have default constructor and implement 'dk.gov.oio.saml.audit.AuditLogger'", clazz.getName()), e);
        }
    }
}
