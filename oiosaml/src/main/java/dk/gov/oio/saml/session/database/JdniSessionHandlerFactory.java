package dk.gov.oio.saml.session.database;

import dk.gov.oio.saml.config.Configuration;
import dk.gov.oio.saml.session.SessionHandler;
import dk.gov.oio.saml.session.SessionHandlerFactory;
import dk.gov.oio.saml.util.InternalException;
import org.opensaml.core.config.InitializationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;

public class JdniSessionHandlerFactory implements SessionHandlerFactory {
    private static final Logger log = LoggerFactory.getLogger(JdniSessionHandlerFactory.class);

    private SessionHandler handler;

    public JdniSessionHandlerFactory() {
    }

    /**
     * Get a session handler.
     *
     * @return session handler instance
     */
    @Override
    public SessionHandler getHandler() throws InternalException {
        if (null == handler) {
            throw new InternalException("Please call configure before getHandler");
        }
        return handler;
    }

    /**
     * Close the factory. No calls to {@link #getHandler()} will be made after this call.
     * <p>
     * Be aware that this method might be called several times, and should not fail if this happens.
     */
    @Override
    public void close() {
        log.debug("Closing factory with handler '{}'",handler);
        handler = null;
    }

    /**
     * Configure the factory. This will be called before any calls are made to {@link #getHandler()}.
     *
     * @param config OIOSAML configuration
     */
    @Override
    public void configure(Configuration config) throws InitializationException {
        try {
            InitialContext ctx = new InitialContext();
            DataSource ds = (DataSource) ctx.lookup(config.getSessionHandlerJndiName());

            this.handler = new DatabaseSessionHandler(ds);
        } catch (NamingException e) {
            throw new InitializationException("Unable to create JNDI database session handler", e);
        }
    }
}
