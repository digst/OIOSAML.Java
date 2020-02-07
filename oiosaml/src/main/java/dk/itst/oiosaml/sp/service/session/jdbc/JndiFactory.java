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
package dk.itst.oiosaml.sp.service.session.jdbc;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;

import org.apache.commons.configuration.Configuration;

import dk.itst.oiosaml.sp.service.session.SessionHandler;
import dk.itst.oiosaml.sp.service.session.SessionHandlerFactory;

/**
 * Factory for creating {@link JdbcSessionHandler} objects.
 * 
 * This requires a JNDI resource to be configured, and the name must be present in the configuration 
 * under the property <strong>oiosaml-sp.sessionhandler.jndi</strong>.
 * 
 * @author recht
 *
 */
public class JndiFactory implements SessionHandlerFactory {

	private String name;

	public void close() {
		
	}

	public void configure(Configuration config) {
		name = config.getString("oiosaml-sp.sessionhandler.jndi");
	}

	public SessionHandler getHandler() {
		try {
			InitialContext ctx = new InitialContext();
			DataSource ds = (DataSource) ctx.lookup(name);
			
			return new JdbcSessionHandler(ds);
		} catch (NamingException e) {
			throw new RuntimeException(e);
		}
	}

}
