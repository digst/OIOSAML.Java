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
package dk.itst.oiosaml.sp.service.session;

import dk.itst.oiosaml.logging.Logger;
import dk.itst.oiosaml.logging.LoggerFactory;
import org.apache.commons.configuration.Configuration;

import dk.itst.oiosaml.sp.service.util.Constants;
import dk.itst.oiosaml.sp.service.util.Utils;

/**
 * Factory for creating new session handlers.
 * 
 * Normally, only one instance of a factory is created (using {@link Factory}), so implementations must be thread safe.
 */
public interface SessionHandlerFactory {

	/**
	 * Get a new session handler.
	 */
	public SessionHandler getHandler();
	
	/**
	 * Close the factory. No calls to {@link #getHandler()} will be made after this call.
	 * 
	 * Be aware that this method might be called several times, and should not fail if this happens.
	 */
	public void close();

	/**
	 * Configure the factory. This will be called before any calls are made to {@link #getHandler()}.
	 */
	public void configure(Configuration config);

	
	public static class Factory {
		private static final Logger log = LoggerFactory.getLogger(SessionHandlerFactory.class);
		
		private static SessionHandlerFactory instance;

		public static synchronized SessionHandlerFactory newInstance(Configuration configuration) {
			if (log.isDebugEnabled()) log.debug("Creating new handler factory: " + instance + ", config: " + configuration);
			
			if (instance != null) return instance;
			
			if (configuration == null) return null;

			String name = configuration.getString(Constants.PROP_SESSION_HANDLER_FACTORY);
			if (log.isDebugEnabled()) log.debug("Using session handler factory class: " + name);

			SessionHandlerFactory factory = (SessionHandlerFactory) Utils.newInstance(configuration, Constants.PROP_SESSION_HANDLER_FACTORY);
			factory.configure(configuration);
			
			instance = factory;
			
			return factory;
		}
		
		public static void close() {
			instance = null;
		}
	}
	
}
