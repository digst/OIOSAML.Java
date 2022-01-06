package dk.gov.oio.saml.session;

import dk.gov.oio.saml.config.Configuration;
import dk.gov.oio.saml.session.inmemory.InMemorySessionHandler;
import dk.gov.oio.saml.session.inmemory.InMemorySessionHandlerFactory;
import dk.gov.oio.saml.util.InternalException;
import org.mockito.Mockito;
import org.opensaml.core.config.InitializationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TestSessionHandlerFactory implements SessionHandlerFactory {
    private static final Logger log = LoggerFactory.getLogger(InMemorySessionHandlerFactory.class);

    private SessionHandler handler;

    public TestSessionHandlerFactory() {
    }

    public void setHandler(SessionHandler handler) {
        this.handler = handler;
    }

    @Override
    public SessionHandler getHandler() throws InternalException {
        if (null == handler) {
            throw new InternalException("Please call configure before getHandler");
        }
        return handler;
    }

    @Override
    public void close() {
        log.debug("Closing factory with handler '{}'",handler);
        handler = null;
    }

    @Override
    public synchronized void configure(Configuration config) throws InitializationException {
        if (null == handler) {
            handler = Mockito.mock(SessionHandler.class);
        }
    }
}
