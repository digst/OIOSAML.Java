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

import dk.gov.oio.saml.audit.AuditService;
import dk.gov.oio.saml.model.NSISLevel;
import dk.gov.oio.saml.service.OIOSAML3Service;
import dk.gov.oio.saml.session.AssertionWrapper;
import dk.gov.oio.saml.session.AuthnRequestWrapper;
import dk.gov.oio.saml.session.LogoutRequestWrapper;
import dk.gov.oio.saml.session.SessionHandler;
import dk.gov.oio.saml.session.inmemory.TimeOutWrapper;
import dk.gov.oio.saml.util.InternalException;
import dk.gov.oio.saml.util.StringUtil;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.apache.commons.codec.binary.Base64;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpSession;
import javax.sql.DataSource;
import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.sql.*;
import java.time.Clock;
import java.util.Date;

/**
 * Handle session state across requests and instances, using a database as session storage.
 */
public class DatabaseSessionHandler implements SessionHandler {
    private static final Logger log = LoggerFactory.getLogger(DatabaseSessionHandler.class);

    private final DataSource ds;

    public DatabaseSessionHandler(DataSource ds) {
        log.debug("Created database session handler");
        this.ds = ds;
    }
    /**
     * Set AuthnRequest on the current session
     *
     * @param session HTTP session
     * @param request {@link AuthnRequestWrapper}
     * @throws InternalException on failure to persist request
     */
    @Override
    public void storeAuthnRequest(HttpSession session, AuthnRequestWrapper request) throws InternalException {
        if (null == request || null == request.getId()) {
            log.warn("Ignore AuthRequest with null value or missing ID");
            return;
        }
        try (Connection connection=ds.getConnection()){
            connection.setAutoCommit(true);

            AuthnRequestWrapper authnRequest = getAuthnRequest(session);
            if (null != authnRequest) {
                log.debug("AuthRequest '{}' will replace '{}'", request.getId(), authnRequest.getId());
                try (PreparedStatement ps = connection.prepareStatement("DELETE FROM authn_requests_tbl WHERE session_id = ?")) {
                    ps.setString(1, getSessionId(session));
                    ps.executeUpdate();
                }
            }
            log.debug("Store AuthRequest '{}'", request.getId());
            try(PreparedStatement ps = connection.prepareStatement("INSERT INTO authn_requests_tbl (session_id, access_time, nsis_level, request_path, xml_object) VALUES (?,?,?,?,?)")) {
                ps.setString(1, getSessionId(session));
                ps.setTimestamp(2, Timestamp.valueOf(java.time.LocalDateTime.now(Clock.systemDefaultZone())));
                ps.setString(3, request.getRequestedNsisLevel().name());
                ps.setString(4, request.getRequestPath());
                ps.setClob(5, new StringReader(request.getAuthnRequestAsBase64()));
                ps.executeUpdate();
            }

        } catch (SQLException e) {
            log.error("Failure to persist authn request", e);
            throw new InternalException("Failure to persist authn request", e);
        }
    }

    /**
     * Set Assertion on the current session
     *
     * @param session   HTTP session
     * @param assertion {@link AssertionWrapper}
     * @throws InternalException on failure to persist request
     */
    @Override
    public void storeAssertion(HttpSession session, AssertionWrapper assertion) throws InternalException {
        if (null == assertion || StringUtil.isEmpty(assertion.getID())) {
            log.warn("Ignore Assertion with null value or missing ID");
            return;
        }
        if (StringUtil.isEmpty(assertion.getSessionIndex())) {
            log.info("Assertion '{}' with passive session and missing index", assertion.getID());
        }

        try (Connection connection=ds.getConnection()){
            connection.setAutoCommit(true);

            try(PreparedStatement ps = connection.prepareStatement("SELECT '1' FROM replay_tbl WHERE assertion_id = ?")) {
                ps.setString(1, assertion.getID());
                try(ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        throw new IllegalArgumentException(String.format("Assertion with id '%s' and session index '%s' is already registered", assertion.getID(), assertion.getSessionIndex()));
                    }
                }
            }

            AssertionWrapper existingAssertion = getAssertion(session);
            if (null != existingAssertion) {
                if (assertion.isReplayOf(existingAssertion)) {
                    log.debug("Assertion '{}' is being replayed", assertion.getID(), existingAssertion.getID());
                    throw new IllegalArgumentException(String.format("Assertion with id '%s' and session index '%s' is already registered", assertion.getID(), assertion.getSessionIndex()));
                }

                log.debug("Assertion '{}' will replace '{}'", assertion.getID(), existingAssertion.getID());
                try (PreparedStatement ps = connection.prepareStatement("DELETE FROM assertions_tbl WHERE session_id = ?")) {
                    ps.setString(1, getSessionId(session));
                    ps.executeUpdate();
                }
            }

            log.debug("Store Assertion '{}'", assertion.getID());
            try(PreparedStatement ps = connection.prepareStatement("INSERT INTO assertions_tbl (session_id, session_index, assertion_id, subject_name_id, access_time, xml_object) VALUES (?,?,?,?,?,?)")) {
                ps.setString(1, getSessionId(session));
                ps.setString(2, StringUtil.defaultIfEmpty(assertion.getSessionIndex(),assertion.getID()));
                ps.setString(3, assertion.getID());
                ps.setString(4, assertion.getSubjectNameId());
                ps.setTimestamp(5, Timestamp.valueOf(java.time.LocalDateTime.now(Clock.systemDefaultZone())));
                ps.setClob(6, new StringReader(assertion.getAssertionAsBase64()));
                ps.executeUpdate();
            }

            log.debug("Add replay entry for assertion '{}'", assertion.getID());
            try(PreparedStatement ps = connection.prepareStatement("INSERT INTO replay_tbl (assertion_id, access_time) VALUES (?,?)")) {
                ps.setString(1, assertion.getID());
                ps.setTimestamp(2, Timestamp.valueOf(java.time.LocalDateTime.now(Clock.systemDefaultZone())));
                ps.executeUpdate();
            }

        } catch (SQLException e) {
            log.error("Failure to persist assertion", e);
            throw new InternalException("Failure to persist assertion", e);
        }
    }

    /**
     * Set LogoutRequest on the current session
     *
     * @param session HTTP session
     * @param request {@link LogoutRequest}
     * @throws InternalException on failure to persist request
     */
    @Override
    public void storeLogoutRequest(HttpSession session, LogoutRequestWrapper request) throws InternalException {
        if (null == request || null == request.getID()) {
            log.warn("Ignore LogoutRequest with null value or missing ID");
            return;
        }
        try (Connection connection=ds.getConnection()){
            connection.setAutoCommit(true);

            LogoutRequestWrapper logoutRequest = getLogoutRequest(session);
            if (null != logoutRequest) {
                log.debug("LogoutRequest '{}' will replace '{}'", request.getID(), logoutRequest.getID());
                try (PreparedStatement ps = connection.prepareStatement("DELETE FROM logout_requests_tbl WHERE session_id = ?")) {
                    ps.setString(1, getSessionId(session));
                    ps.executeUpdate();
                }
            }
            log.debug("Store LogoutRequest '{}'", request.getID());
            try(PreparedStatement ps = connection.prepareStatement("INSERT INTO logout_requests_tbl (session_id, access_time, xml_object) VALUES (?,?,?)")) {
                ps.setString(1, getSessionId(session));
                ps.setTimestamp(2, Timestamp.valueOf(java.time.LocalDateTime.now(Clock.systemDefaultZone())));
                ps.setClob(3, new StringReader(request.getLogoutRequestAsBase64()));
                ps.executeUpdate();
            }

        } catch (SQLException e) {
            log.error("Failure to persist logout request", e);
            throw new InternalException("Failure to persist logout request", e);
        }
    }

    /**
     * Get Assertion from the current session
     *
     * @param session HTTP session
     * @return Assertion from current session
     */
    @Override
    public AssertionWrapper getAssertion(HttpSession session) {
        return getAssertionFromSessionId(getSessionId(session));
    }

    /**
     * Get Assertion matching sessionIndex
     *
     * @param sessionIndex OPENSAML sessionIndex
     * @return Assertion matching sessionIndex
     */
    @Override
    public AssertionWrapper getAssertion(String sessionIndex) {
        return getAssertionFromSessionId(getSessionId(sessionIndex));
    }

    /**
     * Get AuthnRequest from the current session
     *
     * @param session HTTP session
     * @return AuthnRequest from current session
     */
    @Override
    public AuthnRequestWrapper getAuthnRequest(HttpSession session) {
        try (Connection connection=ds.getConnection()){
            connection.setAutoCommit(true);

            AuthnRequestWrapper authnRequestWrapper = null;

            try(PreparedStatement ps = connection.prepareStatement("SELECT xml_object, nsis_level, request_path FROM authn_requests_tbl WHERE session_id = ?")) {
                ps.setString(1, getSessionId(session));
                try(ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        authnRequestWrapper = new AuthnRequestWrapper(
                                (AuthnRequest) StringUtil.base64ToXMLObject(rs.getString(1)),
                                NSISLevel.valueOf(rs.getString(2)),
                                rs.getString(3));
                    }
                }
            }

            if (null != authnRequestWrapper) {
                try(PreparedStatement ps = connection.prepareStatement("UPDATE authn_requests_tbl SET access_time = ? WHERE session_id = ?")) {
                    ps.setTimestamp(1, Timestamp.valueOf(java.time.LocalDateTime.now(Clock.systemDefaultZone())));
                    ps.setString(2, getSessionId(session));
                    ps.executeUpdate();
                }
            }

            return authnRequestWrapper;

        } catch (SQLException | InternalException e) {
            log.error("Failed retrieving authn request matching sessionId", e);
            throw new RuntimeException("Failed retrieving authn request matching sessionId", e);
        }
    }

    /**
     * Get LogoutRequest from current session
     *
     * @param session HTTP session
     * @return LogoutRequest from current session
     */
    @Override
    public LogoutRequestWrapper getLogoutRequest(HttpSession session) {
        try (Connection connection=ds.getConnection()){
            connection.setAutoCommit(true);

            LogoutRequestWrapper logoutRequestWrapper = null;

            try(PreparedStatement ps = connection.prepareStatement("SELECT xml_object FROM logout_requests_tbl WHERE session_id = ?")) {
                ps.setString(1, getSessionId(session));
                try(ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        logoutRequestWrapper = new LogoutRequestWrapper((LogoutRequest) StringUtil.base64ToXMLObject(rs.getString(1)));
                    }
                }
            }

            if (null != logoutRequestWrapper) {
                try (PreparedStatement ps = connection.prepareStatement("UPDATE logout_requests_tbl SET access_time = ? WHERE session_id = ?")) {
                    ps.setTimestamp(1, Timestamp.valueOf(java.time.LocalDateTime.now(Clock.systemDefaultZone())));
                    ps.setString(2, getSessionId(session));
                    ps.executeUpdate();
                }
            }

            return logoutRequestWrapper;

        } catch (SQLException | InternalException e) {
            log.error("Failed retrieving authn request matching sessionId", e);
            throw new RuntimeException("Failed retrieving authn request matching sessionId", e);
        }
    }

    /**
     * Get OIOSAML session ID for session with session index
     *
     * @param sessionIndex Session index to lookup session ID for
     * @return OIOSAML session ID (for audit logging)
     */
    @Override
    public String getSessionId(String sessionIndex) {
        try (Connection connection=ds.getConnection()){
            connection.setAutoCommit(true);

            try(PreparedStatement ps = connection.prepareStatement("SELECT session_id FROM assertions_tbl WHERE session_index = ?")) {
                ps.setString(1, sessionIndex);
                try(ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        return rs.getString(1);
                    }
                }
            }

        } catch (SQLException e) {
            log.error("Failed retrieving sessionId from session index '{}'", sessionIndex, e);
            throw new RuntimeException("Failed retrieving sessionId from session index", e);
        }
        return null;
    }

    /**
     * Invalidate current session and assertion
     *
     * @param session   session to invalidate
     * @param assertion assertion to invalidate
     */
    @Override
    public void logout(HttpSession session, AssertionWrapper assertion) {
        log.debug("Logout from session '{}' and assertion '{}'",
                null != session ? getSessionId(session) : "",
                null != assertion ? assertion.getID() : "");

        if (null != assertion
                && StringUtil.isNotEmpty(assertion.getSessionIndex())) {
            logout(getSessionId(assertion.getSessionIndex()));
        }
        logout(getSessionId(session));
    }

    /**
     * Clean stored ids and sessions.
     *
     * @param maxInactiveIntervalSeconds Milliseconds to store session, before it should be invalidated.
     */
    @Override
    public void cleanup(final long maxInactiveIntervalSeconds) {
        try (Connection connection=ds.getConnection()){
            connection.setAutoCommit(true);

            final long replayCleanupDelay = (long) 24 * 60 * 60; /* Save replay for a day */

            try(PreparedStatement ps = connection.prepareStatement("SELECT session_id, assertion_id, subject_name_id FROM assertions_tbl WHERE access_time < ?")) {
                ps.setTimestamp(1, Timestamp.valueOf(java.time.LocalDateTime
                        .now(Clock.systemDefaultZone())
                        .minusSeconds(maxInactiveIntervalSeconds)));
                try(ResultSet rs = ps.executeQuery()) {
                    while(rs.next()) {
                        OIOSAML3Service.getAuditService().auditLog(new AuditService
                                .Builder()
                                .withAuthnAttribute("ACTION", "TIMEOUT")
                                .withAuthnAttribute("DESCRIPTION", "SessionDestroyed")
                                .withAuthnAttribute("SP_SESSION_ID", rs.getString(1))
                                .withAuthnAttribute("ASSERTION_ID", rs.getString(2))
                                .withAuthnAttribute("SUBJECT_NAME_ID", rs.getString(3)));
                    }
                }
            }

            try(PreparedStatement ps = connection.prepareStatement("DELETE FROM assertions_tbl WHERE access_time < ?")) {
                ps.setTimestamp(1, Timestamp.valueOf(java.time.LocalDateTime
                        .now(Clock.systemDefaultZone())
                        .minusSeconds(maxInactiveIntervalSeconds)));
                ps.executeUpdate();
            }

            try(PreparedStatement ps = connection.prepareStatement("DELETE FROM authn_requests_tbl WHERE access_time < ?")) {
                ps.setTimestamp(1, Timestamp.valueOf(java.time.LocalDateTime
                        .now(Clock.systemDefaultZone())
                        .minusSeconds(maxInactiveIntervalSeconds)));
                ps.executeUpdate();
            }

            try(PreparedStatement ps = connection.prepareStatement("DELETE FROM logout_requests_tbl WHERE access_time < ?")) {
                ps.setTimestamp(1, Timestamp.valueOf(java.time.LocalDateTime
                        .now(Clock.systemDefaultZone())
                        .minusSeconds(maxInactiveIntervalSeconds)));
                ps.executeUpdate();
            }

            try(PreparedStatement ps = connection.prepareStatement("DELETE FROM replay_tbl WHERE access_time < ?")) {
                ps.setTimestamp(1, Timestamp.valueOf(java.time.LocalDateTime
                        .now(Clock.systemDefaultZone())
                        .minusSeconds(replayCleanupDelay)));
                ps.executeUpdate();
            }

        } catch (SQLException e) {
            log.error("Failed running cleanup", e);
        }
    }

    private void logout(String sessionId) {
        log.debug("Invalidate OIOSAML session '{}'", sessionId);
        try (Connection connection=ds.getConnection()) {
            connection.setAutoCommit(true);

            if (StringUtil.isEmpty(sessionId)) {
                return;
            }

            try (PreparedStatement ps = connection.prepareStatement("DELETE FROM assertions_tbl WHERE session_id = ?")) {
                ps.setString(1, sessionId);
                ps.executeUpdate();
            }

        } catch (SQLException e) {
            log.error("Failed logging out", e);
        }
    }

    private AssertionWrapper getAssertionFromSessionId(String sessionId) {
        try (Connection connection=ds.getConnection()){
            connection.setAutoCommit(true);

            AssertionWrapper assertionWrapper = null;

            try(PreparedStatement ps = connection.prepareStatement("SELECT xml_object FROM assertions_tbl WHERE session_id = ?")) {
                ps.setString(1, sessionId);
                try(ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        assertionWrapper = new AssertionWrapper(
                                (Assertion) StringUtil.base64ToXMLObject(rs.getString(1)));
                    }
                }
            }

            if (null != assertionWrapper) {
                try(PreparedStatement ps = connection.prepareStatement("UPDATE assertions_tbl SET access_time = ? WHERE session_id = ?")) {
                    ps.setTimestamp(1, Timestamp.valueOf(java.time.LocalDateTime.now(Clock.systemDefaultZone())));
                    ps.setString(2, sessionId);
                    ps.executeUpdate();
                }
            }

            return assertionWrapper;

        } catch (SQLException | InternalException e) {
            log.error("Failed retrieving assertion matching sessionId", e);
            throw new RuntimeException("Failed retrieving assertion matching sessionId", e);
        }
    }
}
