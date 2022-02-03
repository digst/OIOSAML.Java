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
package dk.gov.oio.saml.session;

import dk.gov.oio.saml.config.Configuration;
import dk.gov.oio.saml.util.InternalException;
import org.opensaml.core.config.InitializationException;

/**
 * Factory for creating session handlers.
 *
 * Normally, only one instance of a factory is created (using {@link InternalSessionHandlerFactory}), so implementations must be thread safe.
 */
public interface SessionHandlerFactory {

    /**
     * Get a session handler.
     * @return session handler instance
     * @throws InternalException on failure to get session handler
     */
    SessionHandler getHandler() throws InternalException;

    /**
     * Close the factory. No calls to {@link #getHandler()} will be made after this call.
     *
     * Be aware that this method might be called several times, and should not fail if this happens.
     */
    void close();

    /**
     * Configure the factory. This will be called before any calls are made to {@link #getHandler()}.
     * @param config OIOSAML configuration
     * @throws InitializationException on failure to initialize factory
     */
    void configure(Configuration config) throws InitializationException;
}
