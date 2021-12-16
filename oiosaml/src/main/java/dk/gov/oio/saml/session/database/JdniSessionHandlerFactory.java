package dk.gov.oio.saml.session.database;

import dk.gov.oio.saml.config.Configuration;
import dk.gov.oio.saml.session.SessionHandler;
import dk.gov.oio.saml.session.SessionHandlerFactory;
import dk.gov.oio.saml.util.InternalException;
import org.opensaml.core.config.InitializationException;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;

public class JdniSessionHandlerFactory implements SessionHandlerFactory {

    private String name;

    public JdniSessionHandlerFactory() {
    }

    /**
     * Get a new session handler.
     *
     * @return session handler instance
     */
    @Override
    public SessionHandler getHandler() throws InternalException {
        try {
            InitialContext ctx = new InitialContext();
            DataSource ds = (DataSource) ctx.lookup(name);

            return new DatabaseSessionHandler(ds);
        } catch (NamingException e) {
            throw new InternalException("Unable to create JNDI database session handler", e);
        }
    }

    /**
     * Close the factory. No calls to {@link #getHandler()} will be made after this call.
     * <p>
     * Be aware that this method might be called several times, and should not fail if this happens.
     */
    @Override
    public void close() {
    }

    /**
     * Configure the factory. This will be called before any calls are made to {@link #getHandler()}.
     *
     * @param config OIOSAML configuration
     */
    @Override
    public void configure(Configuration config) throws InitializationException {
        name = config.getSessionHandlerJndiName();
    }
}
