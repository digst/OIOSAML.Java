package dk.gov.oio.saml.session.database;

import dk.gov.oio.saml.config.Configuration;
import dk.gov.oio.saml.session.SessionHandler;
import dk.gov.oio.saml.session.SessionHandlerFactory;
import dk.gov.oio.saml.util.InternalException;
import org.opensaml.core.config.InitializationException;

public class JdbcSessionHandlerFactory implements SessionHandlerFactory {

    public JdbcSessionHandlerFactory() {
    }

    /**
     * Get a new session handler.
     *
     * @return session handler instance
     */
    @Override
    public SessionHandler getHandler() throws InternalException {
        throw new UnsupportedOperationException("TODO");
    }

    /**
     * Close the factory. No calls to {@link #getHandler()} will be made after this call.
     * <p>
     * Be aware that this method might be called several times, and should not fail if this happens.
     */
    @Override
    public void close() {
        throw new UnsupportedOperationException("TODO");
    }

    /**
     * Configure the factory. This will be called before any calls are made to {@link #getHandler()}.
     *
     * @param config OIOSAML configuration
     */
    @Override
    public void configure(Configuration config) throws InitializationException {
        throw new UnsupportedOperationException("TODO");
    }
}