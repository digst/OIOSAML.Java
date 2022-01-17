/*
 * The contents of this file are subject to the Mozilla Public
 * License Version 1.1 (the "License"); you may not use this
 * file except in compliance with the License. You may obtain
 * a copy of the License at http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an
 * "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, either express
 * or implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 *
 * The Original Code is OIOSAML Java Service Provider.
 *
 * The Initial Developer of the Original Code is Trifork A/S. Portions
 * created by Trifork A/S are Copyright (C) 2009 Danish National IT
 * and Telecom Agency (http://www.itst.dk). All Rights Reserved.
 *
 * Contributor(s):
 *   Joakim Recht <jre@trifork.com>
 *   Rolf Njor Jensen <rolf@trifork.com>
 *
 */
package dk.gov.oio.saml.session.inmemory;

import dk.gov.oio.saml.config.Configuration;
import dk.gov.oio.saml.session.SessionHandler;
import dk.gov.oio.saml.session.SessionHandlerFactory;
import dk.gov.oio.saml.util.InternalException;
import org.opensaml.core.config.InitializationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class InMemorySessionHandlerFactory implements SessionHandlerFactory {
    private static final Logger log = LoggerFactory.getLogger(InMemorySessionHandlerFactory.class);

    private SessionHandler handler;

    public InMemorySessionHandlerFactory() {
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
    public synchronized void configure(Configuration config) throws InitializationException {
        if (null == handler) {
            handler = new InMemorySessionHandler(config.getSessionHandlerInMemoryMaxNumTrackedSessionIds());
        }
    }
}
