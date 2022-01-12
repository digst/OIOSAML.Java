package dk.gov.oio.saml.session.database;

import dk.gov.oio.saml.config.Configuration;
import dk.gov.oio.saml.session.SessionHandler;
import dk.gov.oio.saml.session.SessionHandlerFactory;
import dk.gov.oio.saml.util.InternalException;
import dk.gov.oio.saml.util.StringUtil;
import org.opensaml.core.config.InitializationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;

public class JdbcSessionHandlerFactory implements SessionHandlerFactory {

    private static final Logger log = LoggerFactory.getLogger(JdbcSessionHandlerFactory.class);

    private SessionHandler handler;

    public JdbcSessionHandlerFactory() {
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
        final String url = config.getSessionHandlerJdbcUrl();
        final String username = config.getSessionHandlerJdbcUsername();
        final String password = config.getSessionHandlerJdbcPassword();
        final String driver = config.getSessionHandlerJdbcDriverClassName();

        try {
            Class.forName(driver);
        } catch (ClassNotFoundException e) {
            throw new InitializationException(String.format("Unable to load driver '%s'", driver), e);
        }

        this.handler = new DatabaseSessionHandler(new DataSource() {
            @Override
            public Connection getConnection() throws SQLException {
                return StringUtil.isNotEmpty(username)?
                        DriverManager.getConnection(url, username, password) :
                        DriverManager.getConnection(url);
            }

            @Override
            public Connection getConnection(String usernameInput, String passwordInput) throws SQLException {
                throw new UnsupportedOperationException("Unsupported method");
            }

            @Override
            public PrintWriter getLogWriter() throws SQLException {
                throw new UnsupportedOperationException("Unsupported method");
            }

            @Override
            public void setLogWriter(PrintWriter out) throws SQLException {
                throw new UnsupportedOperationException("Unsupported method");
            }

            @Override
            public void setLoginTimeout(int seconds) throws SQLException {
                throw new UnsupportedOperationException("Unsupported method");
            }

            @Override
            public int getLoginTimeout() throws SQLException {
                throw new UnsupportedOperationException("Unsupported method");
            }

            @Override
            public <T> T unwrap(Class<T> iface) throws SQLException {
                throw new UnsupportedOperationException("Unsupported method");
            }

            @Override
            public boolean isWrapperFor(Class<?> iface) throws SQLException {
                throw new UnsupportedOperationException("Unsupported method");
            }

            @Override
            public java.util.logging.Logger getParentLogger() throws SQLFeatureNotSupportedException {
                return null;
            }
        });
    }
}
