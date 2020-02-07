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

import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.logging.Logger;

import javax.sql.DataSource;

import org.apache.commons.configuration.Configuration;

import dk.itst.oiosaml.sp.service.session.SessionHandler;
import dk.itst.oiosaml.sp.service.session.SessionHandlerFactory;

/**
 * Session factory which uses plain old jdbc connections.
 * 
 * The following properties must be set in the configuration:
 * <ul>
 * <li>oiosaml-sp.sessionhandler.factory=dk.itst.oiosaml.sp.service.session.jdbc.JndiFactory</li>
 * <li>oiosaml-sp.sessionhandler.jdbc.url: JDBC url to use for the connetion</li>
 * <li>oiosaml-sp.sessionhandler.jdbc.driver: Driver class name to use</li>
 * <li>oiosaml-sp.sessionhandler.jdbc.username</li>
 * <li>oiosaml-sp.sessionhandler.jdbc.password</li>
 * </ul>
 * 
 * @author Joakim Recht
 * 
 */
public class JdbcFactory implements SessionHandlerFactory {

	private String url;
	private String username;
	private String password;
	private String driver;

	public void close() {

	}

	public void configure(Configuration config) {
		url = config.getString("oiosaml-sp.sessionhandler.jdbc.url");
		username = config.getString("oiosaml-sp.sessionhandler.jdbc.username");
		password = config.getString("oiosaml-sp.sessionhandler.jdbc.password");
		driver = config.getString("oiosaml-sp.sessionhandler.jdbc.driver");

		try {
			Class.forName(driver);
		} catch (ClassNotFoundException e) {
			throw new RuntimeException("Unable to load driver " + driver, e);
		}
	}

	public SessionHandler getHandler() {
		return new JdbcSessionHandler(new DS());
	}

	private class DS implements DataSource {
		public Connection getConnection() throws SQLException {
			return DriverManager.getConnection(url, username, password);
		}

		public Connection getConnection(String usernm, String passwd)
				throws SQLException {
			throw new UnsupportedOperationException();
		}

		public PrintWriter getLogWriter() throws SQLException {
			throw new UnsupportedOperationException();
		}

		public int getLoginTimeout() throws SQLException {
			throw new UnsupportedOperationException();
		}

		public void setLogWriter(PrintWriter out) throws SQLException {
			throw new UnsupportedOperationException();
		}

		public void setLoginTimeout(int seconds) throws SQLException {
			throw new UnsupportedOperationException();
		}

		public boolean isWrapperFor(Class<?> iface) throws SQLException {
			throw new UnsupportedOperationException();
		}

		public <T> T unwrap(Class<T> iface) throws SQLException {
			throw new UnsupportedOperationException();
		}

		public Logger getParentLogger() throws SQLFeatureNotSupportedException {
			// TODO Auto-generated method stub
			return null;
		}
	}
}
