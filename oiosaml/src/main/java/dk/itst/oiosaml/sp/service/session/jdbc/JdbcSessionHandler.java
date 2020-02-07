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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Date;

import javax.servlet.http.HttpSession;
import javax.sql.DataSource;

import dk.itst.oiosaml.logging.Logger;
import dk.itst.oiosaml.logging.LoggerFactory;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.xml.util.Base64;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.service.session.Request;
import dk.itst.oiosaml.sp.service.session.SessionHandler;
import dk.itst.oiosaml.sp.service.util.Constants;
import dk.itst.oiosaml.sp.service.util.Utils;

public class JdbcSessionHandler implements SessionHandler {
	private static final Logger log = LoggerFactory.getLogger(JdbcSessionHandler.class);
	private final DataSource ds;
	private static int uniqueId = 0;
	private static int counter = 0;

	public JdbcSessionHandler(DataSource ds) {
		this.ds = ds;
	}

	private Connection getConnection() {
		try {
			Connection c = ds.getConnection();
			c.setAutoCommit(true);
			return c;
		}
		catch (SQLException e) {
			throw new RuntimeException(e);
		}
	}

	private static void closeConnection(Connection connection) {
		if (connection == null)
			return;
		try {
			connection.close();
		}
		catch (SQLException e) {
			log.error("Unable to close connection", e);
		}
	}

	public void cleanup(long requestIdsCleanupDelay, long sessionCleanupDelay) {
		Connection con = getConnection();
		String[] tables = new String[] { "assertions", "requests", "requestdata" };

		try {
			for (String table : tables) {
				PreparedStatement ps = con.prepareStatement("DELETE FROM " + table + " WHERE timestamp < ?");
				ps.setTimestamp(1, new Timestamp(new Date().getTime() - sessionCleanupDelay));
				ps.executeUpdate();
			}
		}
		catch (SQLException e) {
			throw new RuntimeException(e);
		}
		finally {
			closeConnection(con);
		}
	}

	public OIOAssertion getAssertion(String sessionId) {
		Connection con = getConnection();
		try {
			PreparedStatement ps = con.prepareStatement("SELECT assertion FROM assertions WHERE id = ?");
			ps.setString(1, sessionId);
			ResultSet rs = ps.executeQuery();
			if (rs.next()) {
				OIOAssertion res = new OIOAssertion((Assertion) SAMLUtil.unmarshallElementFromString(rs.getString("assertion")));
				updateTimestamp(sessionId, con);

				return res;
			}

			return null;
		}
		catch (SQLException e) {
			throw new RuntimeException(e);
		}
		finally {
			closeConnection(con);
		}
	}

	private static void updateTimestamp(String id, Connection con) throws SQLException {
		PreparedStatement ps = con.prepareStatement("UPDATE assertions SET timestamp = ? WHERE id = ?");
		ps.setTimestamp(1, new Timestamp(new Date().getTime()));
		ps.setString(2, id);
		ps.executeUpdate();
		ps.close();
	}

	public String getRelatedSessionId(String sessionIndex) {
		Connection con = getConnection();
		try {
			PreparedStatement ps = con.prepareStatement("SELECT id FROM assertions WHERE sessionindex = ?");
			ps.setString(1, sessionIndex);
			ResultSet rs = ps.executeQuery();
			if (rs.next()) {
				return rs.getString("id");
			}

			return null;
		}
		catch (SQLException e) {
			throw new RuntimeException(e);
		}
		finally {
			closeConnection(con);
		}
	}

	public Request getRequest(String state) throws IllegalArgumentException {
		Connection con = getConnection();
		try {
			PreparedStatement ps = con.prepareStatement("SELECT data FROM requestdata WHERE id = ?");
			ps.setString(1, state);
			ResultSet rs = ps.executeQuery();
			if (rs.next()) {
				ObjectInputStream is = new ObjectInputStream(new ByteArrayInputStream(Base64.decode(rs.getString("data"))));
				Request result = (Request) is.readObject();

				ps = con.prepareStatement("DELETE FROM requestdata where id = ?");
				ps.setString(1, state);
				ps.executeUpdate();

				return result;
			}

			throw new IllegalArgumentException("No state with " + state + " registered");
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
		finally {
			closeConnection(con);
		}
	}

	public boolean isLoggedIn(String sessionId) {
		OIOAssertion ass = getAssertion(sessionId);
		return ass != null && !ass.hasSessionExpired();
	}

	public void logOut(HttpSession session) {
		session.removeAttribute(Constants.SESSION_USER_ASSERTION);
		logOut(session.getId());
	}

	public void logOut(String sessionId) {
		Connection con = getConnection();
		try {
			PreparedStatement ps = con.prepareStatement("DELETE FROM assertions WHERE id = ?");
			ps.setString(1, sessionId);
			ps.executeUpdate();
			ps.close();
		}
		catch (SQLException e) {
			throw new RuntimeException(e);
		}
		finally {
			closeConnection(con);
		}
	}

	public void registerRequest(String id, String receiverEntityID) {
		Connection con = getConnection();
		try {
			PreparedStatement ps = con.prepareStatement("INSERT INTO requests (id, receiver, timestamp) VALUES (?, ?, ?)");
			ps.setString(1, id);
			ps.setString(2, receiverEntityID);
			ps.setTimestamp(3, new Timestamp(new Date().getTime()));
			ps.executeUpdate();
			ps.close();
		}
		catch (SQLException e) {
			throw new RuntimeException(e);
		}
		finally {
			closeConnection(con);
		}
	}

	public String removeEntityIdForRequest(String id) {
		Connection con = getConnection();
		try {
			PreparedStatement ps = con.prepareStatement("SELECT receiver FROM requests WHERE id = ?");
			ps.setString(1, id);
			ResultSet rs = ps.executeQuery();
			if (rs.next()) {
				return rs.getString("receiver");
			}

			throw new IllegalArgumentException("Request with id " + id + " is unknown");
		}
		catch (SQLException e) {
			throw new RuntimeException(e);
		}
		finally {
			closeConnection(con);
		}
	}

	public void resetReplayProtection(int maxNum) {
		Connection con = getConnection();
		try {
			PreparedStatement ps = con.prepareStatement("DELETE FROM assertions");
			ps.executeUpdate();
		}
		catch (SQLException e) {
			throw new RuntimeException(e);
		}
		finally {
			closeConnection(con);
		}
	}

	public String saveRequest(Request request) {
		Connection con = getConnection();
		try {
			String state = Utils.generateUUID();
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			ObjectOutputStream oos = new ObjectOutputStream(bos);
			oos.writeObject(request);
			oos.close();

			String s = Base64.encodeBytes(bos.toByteArray());

			PreparedStatement ps = con.prepareStatement("INSERT INTO requestdata (id, data, timestamp) VALUES (?, ?, ?)");
			ps.setString(1, state);
			ps.setString(2, s);
			ps.setTimestamp(3, new Timestamp(new Date().getTime()));
			ps.executeUpdate();

			return state;
		}
		catch (SQLException e) {
			throw new RuntimeException(e);
		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}
		finally {
			closeConnection(con);
		}
	}

	public void setAssertion(String sessionId, OIOAssertion assertion) throws IllegalArgumentException {
		Connection con = getConnection();
		try {
			PreparedStatement ps = con.prepareStatement("SELECT 1 FROM assertions WHERE assertionid = ? OR sessionindex = ?");
			ps.setString(1, assertion.getID());
			ps.setString(2, assertion.getSessionIndex());
			ResultSet rs = ps.executeQuery();
			if (rs.next()) {
				throw new IllegalArgumentException("Assertion with id " + assertion.getID() + " and sessionidx " + assertion.getSessionIndex() + " is already registered");
			}
			ps.close();

			ps = con.prepareStatement("DELETE FROM assertions WHERE id = ? OR sessionindex = ?");
			ps.setString(1, sessionId);
			ps.setString(2, assertion.getSessionIndex());
			if (ps.executeUpdate() > 0) {
				log.debug("Overwriting existing session info for session " + sessionId);
			}
			ps.close();

			ps = con.prepareStatement("INSERT INTO assertions (id, assertion, assertionid, sessionindex, timestamp) VALUES (?, ?, ?, ?, ?)");
			ps.setString(1, sessionId);
			ps.setString(2, assertion.toXML());
			ps.setString(3, assertion.getID());

			String sessionIndex = assertion.getSessionIndex();
			if (sessionIndex == null) {
				sessionIndex = getNextPassiveSessionIndex();
			}
			ps.setString(4, sessionIndex);

			ps.setTimestamp(5, new Timestamp(new Date().getTime()));
			ps.execute();
			ps.close();
		}
		catch (SQLException e) {
			throw new RuntimeException(e);
		}
		finally {
			closeConnection(con);
		}
	}

	private String getNextPassiveSessionIndex() {
		String sessionIndex = null;

		synchronized (this) {
			Connection con = null;

			try {
				con = getConnection();

				for (int i = 0; i < 10; i++) { // 10 tries is more than enough: since we are inside a sync-block, it should actually never fail!
					counter++;

					String attemptedSessionIndex = "Passive:" + uniqueId + "x" + counter;

					// check if there already is an active session with this sessionIndex
					PreparedStatement ps = con.prepareStatement("SELECT 1 FROM assertions WHERE sessionindex = ?");
					ps.setString(1, attemptedSessionIndex);
					ResultSet rs = ps.executeQuery();

					if (!rs.next()) {
						sessionIndex = attemptedSessionIndex;
						ps.close();
						break;
					}
					ps.close();
				}
			}
			catch (Exception ex) {
				throw new RuntimeException(ex);
			}
			finally {
				closeConnection(con);
			}
		}

		if (sessionIndex == null) {
			throw new RuntimeException("Failed to aquire a unique sessionIndex for passive-login!");
		}

		return sessionIndex;
	}
}
