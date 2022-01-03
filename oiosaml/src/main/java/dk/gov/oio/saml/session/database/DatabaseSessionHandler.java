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
package dk.gov.oio.saml.session.database;

import dk.gov.oio.saml.model.NSISLevel;
import dk.gov.oio.saml.oiobpp.ObjectFactory;
import dk.gov.oio.saml.oiobpp.PrivilegeList;
import dk.gov.oio.saml.session.AssertionWrapper;
import dk.gov.oio.saml.session.AuthnRequestWrapper;
import dk.gov.oio.saml.session.SessionHandler;
import dk.gov.oio.saml.util.InternalException;
import dk.gov.oio.saml.util.StringUtil;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.apache.commons.codec.binary.Base64;
import org.joda.time.DateTime;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.impl.AssertionMarshaller;
import org.opensaml.saml.saml2.core.impl.AssertionUnmarshaller;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import javax.servlet.http.HttpSession;
import javax.sql.DataSource;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Unmarshaller;
import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.sql.*;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;

public class DatabaseSessionHandler implements SessionHandler {
    private static final Logger log = LoggerFactory.getLogger(DatabaseSessionHandler.class);
    private static int uniqueId = 0;
    private static int counter = 0;

    private final DataSource ds;

    public DatabaseSessionHandler(DataSource ds) {
        log.debug("Created database session handler");
        this.ds = ds;

        // TODO: database scheme + index
        // TODO: wrapper for logout request
        // TODO: logout request wrapper usage i other code?
        // TODO: store requests
        // TODO: get requests (authn + logout)
        // TODO: unit test for everything
        // TODO: documentation
        // TODO:
    }
    /**
     * Set AuthnRequest on the current session
     *
     * @param session HTTP session
     * @param request {@link AuthnRequestWrapper}
     */
    @Override
    public void storeAuthnRequest(HttpSession session, AuthnRequestWrapper request) {

    }

    /**
     * Set Assertion on the current session
     *
     * @param session   HTTP session
     * @param assertion {@link AssertionWrapper}
     */
    @Override
    public void storeAssertion(HttpSession session, AssertionWrapper assertion) {
        try (Connection connection=ds.getConnection()){
            connection.setAutoCommit(true);

            // Create assertion
            try(PreparedStatement ps = connection.prepareStatement("INSERT INTO assertions (sessionId, sessionIndex, subjectNameId,  timestamp, assertion) VALUES (?,?,?,?,?)")) {
                ps.setString(1, session.getId());
                ps.setString(2, assertion.getSessionIndex());
                ps.setString(3, assertion.getSubjectNameId());
                ps.setTimestamp(4, new Timestamp(new Date().getTime()));
                ps.setBytes(5,  assertion2bytes(assertion.getAssertion()));
                ps.executeUpdate();
            }
        } catch (SQLException e) {
            log.error("Failed retrieving assertion matching sessionIndex", e);
            throw new RuntimeException("Failed retrieving assertion matching sessionIndex", e);
        }
    }

    /**
     * Set LogoutRequest on the current session
     *
     * @param session HTTP session
     * @param request {@link LogoutRequest}
     */
    @Override
    public void storeLogoutRequest(HttpSession session, LogoutRequest request) {

    }

    /**
     * Get Assertion from the current session
     *
     * @param session HTTP session
     * @return Assertion from current session
     */
    @Override
    public AssertionWrapper getAssertion(HttpSession session) {
        try (Connection connection=ds.getConnection()){
            connection.setAutoCommit(true);

            // Update assertions timestamp
            try(PreparedStatement ps = connection.prepareStatement("UPDATE assertions SET timestamp = ? WHERE sessionId = ?")) {
                ps.setTimestamp(1, new Timestamp(new Date().getTime()));
                ps.setString(2, session.getId());
                ps.executeUpdate();
            }

            // Retrieve assertion
            try(PreparedStatement ps = connection.prepareStatement("SELECT assertion FROM assertions WHERE sessionId = ?")) {
                ps.setString(1, session.getId());

                try(ResultSet rs = ps.executeQuery()) {
                    return new AssertionWrapper(rs2assertion(rs));
                }
            }
        } catch (SQLException | InternalException e) {
            log.error("Failed retrieving assertion matching sessionId", e);
            throw new RuntimeException("Failed retrieving assertion matching sessionId", e);
        }
    }

    /**
     * Get Assertion matching sessionIndex
     *
     * @param sessionIndex OPENSAML sessionIndex
     * @return Assertion matching sessionIndex
     */
    @Override
    public AssertionWrapper getAssertion(String sessionIndex) {
        try (Connection connection=ds.getConnection()){
            connection.setAutoCommit(true);

            // Update assertions timestamp
            try(PreparedStatement ps = connection.prepareStatement("UPDATE assertions SET timestamp = ? WHERE sessionIndex = ?")) {
                ps.setTimestamp(1, new Timestamp(new Date().getTime()));
                ps.setString(2, sessionIndex);
                ps.executeUpdate();
            }

            // Retrieve assertion
            try(PreparedStatement ps = connection.prepareStatement("SELECT assertion FROM assertions WHERE sessionIndex = ?")) {
                ps.setString(1, sessionIndex);

                try(ResultSet rs = ps.executeQuery()) {
                    return new AssertionWrapper(rs2assertion(rs));
                }
            }
        } catch (SQLException | InternalException e) {
            log.error("Failed retrieving assertion matching sessionIndex", e);
            throw new RuntimeException("Failed retrieving assertion matching sessionIndex", e);
        }
    }

    private byte[] assertion2bytes(Assertion assertion) throws SQLException {
            try {
                return Base64.encodeBase64(SerializeSupport
                        .nodeToString(XMLObjectSupport.marshall(assertion))
                        .getBytes(Charset.forName("UTF-8")));
            } catch (MarshallingException e) {
                log.error("Failed retrieving assertion matching sessionIndex", e);
                throw new RuntimeException("Failed retrieving assertion matching sessionIndex", e);
            }
    }

    private Assertion rs2assertion(ResultSet rs) throws SQLException {
        if (rs.first()) {
            try {
                return (Assertion) XMLObjectSupport.unmarshallFromInputStream(XMLObjectProviderRegistrySupport.getParserPool(), new ByteArrayInputStream(
                        Base64.decodeBase64(rs.getBytes("assertion"))));
            } catch (UnmarshallingException | XMLParserException e) {
                log.error("Failed retrieving assertion matching sessionIndex", e);
                throw new RuntimeException("Failed retrieving assertion matching sessionIndex", e);
            }
        }
        return null;
    }

    /**
     * Get AuthnRequest from the current session
     *
     * @param session HTTP session
     * @return AuthnRequest from current session
     */
    @Override
    public AuthnRequestWrapper getAuthnRequest(HttpSession session) {
        return null;
    }

    /**
     * Get LogoutRequest from current session
     *
     * @param session HTTP session
     * @return LogoutRequest from current session
     */
    @Override
    public LogoutRequest getLogoutRequest(HttpSession session) {
        return null;
    }

    /**
     * Is current session authenticated
     *
     * @param session HTTP session
     * @return true if current session is authenticated
     */
    @Override
    public boolean isAuthenticated(HttpSession session) {
        return false;
    }

    /**
     * Invalidate current session and assertion
     *
     * @param session   session to invalidate
     * @param assertion assertion to invalidate
     */
    @Override
    public void logout(HttpSession session, AssertionWrapper assertion) {

    }

    /**
     * Clean stored ids and sessions.
     *
     * @param maxInactiveIntervalSeconds Milliseconds to store session, before it should be invalidated.
     */
    @Override
    public void cleanup(long maxInactiveIntervalSeconds) {
        try (Connection connection=ds.getConnection()){
            connection.setAutoCommit(true);

            String[] tables = new String[] { "assertions", "requests", "requestdata" };
            final long sessionCleanupDelay = (long)maxInactiveIntervalSeconds * 1000;

            for (String table : tables) {
                try(PreparedStatement ps = connection.prepareStatement("DELETE FROM " + table + " WHERE timestamp < ?")) {
                    ps.setTimestamp(1, new Timestamp(new Date().getTime() - sessionCleanupDelay));
                    ps.executeUpdate();

                }
            }
        } catch (SQLException e) {
            log.error("Failed running cleanup", e);
            throw new RuntimeException("Failed running cleanup", e);
        }
    }
}