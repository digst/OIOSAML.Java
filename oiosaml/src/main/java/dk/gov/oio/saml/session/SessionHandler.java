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
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.LogoutRequest;

import javax.servlet.http.HttpSession;

/**
 * Handle session state across requests and instances.
 *
 * <p>Due to SOAP Logout, it is not possible to store all state in the HTTP session. Instead, implementations of this interface handle session state,
 * primarily based on the HTTP session.</p>
 *
 * <p>Implementations are expected to be thread-safe, and should not store any instance state, as a new instance will be created for
 * every request.</p>
 *
 * @see SessionHandlerFactory
 */
public interface SessionHandler {
    /**
     * Set AuthnRequest on the current session
     * @param session HTTP session
     * @param request {@link AuthnRequestWrapper}
     * @throws InternalException on failure to persist request
     */
    void storeAuthnRequest(HttpSession session, AuthnRequestWrapper request) throws InternalException;

    /**
     * Set Assertion on the current session
     * @param session HTTP session
     * @param assertion {@link AssertionWrapper}
     * @throws InternalException on failure to persist assertion
     */
    void storeAssertion(HttpSession session, AssertionWrapper assertion) throws InternalException;

    /**
     * Set LogoutRequest on the current session
     * @param session HTTP session
     * @param request {@link LogoutRequestWrapper}
     * @throws InternalException on failure to persist request
     */
    void storeLogoutRequest(HttpSession session, LogoutRequestWrapper request) throws InternalException;

    /**
     * Get AuthnRequest from the current session
     * @param session HTTP session
     * @return AuthnRequest from current session
     */
    AuthnRequestWrapper getAuthnRequest(HttpSession session);

    /**
     * Get Assertion from the current session
     * @param session HTTP session
     * @return Assertion from current session
     */
    AssertionWrapper getAssertion(HttpSession session);

    /**
     * Get Assertion matching sessionIndex
     * @param sessionIndex OPENSAML sessionIndex
     * @return Assertion matching sessionIndex
     */
    AssertionWrapper getAssertion(String sessionIndex);

    /**
     * Get LogoutRequest from current session
     * @param session HTTP session
     * @return LogoutRequest from current session
     */
    LogoutRequestWrapper getLogoutRequest(HttpSession session);

    /**
     * Is current session authenticated
     * @param session HTTP session
     * @return true if current session is authenticated
     */
    default boolean isAuthenticated(HttpSession session) {
        AuthnRequestWrapper authnRequestWrapper = getAuthnRequest(session);
        if (null == authnRequestWrapper) {
            return false;
        }
        AssertionWrapper assertionWrapper = getAssertion(session);
        if (null == assertionWrapper) {
            return false;
        }
        return !assertionWrapper.isSessionExpired();
    };

    /**
     * Get OIOSAML session ID for current session
     * @param session HTTP session
     * @return OIOSAML session ID (for audit logging)
     */
    String getSessionId(HttpSession session);

    /**
     * Get OIOSAML session ID for session with session index
     * @param sessionIndex Session index to lookup session ID for
     * @return OIOSAML session ID (for audit logging)
     */
    String getSessionId(String sessionIndex);

    /**
     * Invalidate current session and assertion
     * @param session session to invalidate
     * @param assertion assertion to invalidate
     */
    void logout(HttpSession session, AssertionWrapper assertion);

    /**
     * Clean stored ids and sessions.
     *
     * @param maxInactiveIntervalSeconds Milliseconds to store session, before it should be invalidated.
     */
    void cleanup(long maxInactiveIntervalSeconds);
}
