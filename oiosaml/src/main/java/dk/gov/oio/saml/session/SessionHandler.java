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

import org.opensaml.saml.saml2.core.LogoutRequest;

import javax.servlet.http.HttpSession;

/**
 * Handle session state across requests and instances.
 *
 * <p>Due to SOAP Logout, it is not possible to store all state in the HTTP session. Instead, implementations of this interface handle session state,
 * primarily based on the HTTP session.<p>
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
     */
    void storeAuthnRequest(HttpSession session, AuthnRequestWrapper request);

    /**
     * Set Assertion on the current session
     * @param session HTTP session
     * @param assertion {@link AssertionWrapper}
     */
    void storeAssertion(HttpSession session, AssertionWrapper assertion);

    /**
     * Set LogoutRequest on the current session
     * @param session HTTP session
     * @param request {@link LogoutRequest}
     */
    void storeLogoutRequest(HttpSession session, LogoutRequest request);

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
    LogoutRequest getLogoutRequest(HttpSession session);

    /**
     * Is current session authenticated
     * @param session HTTP session
     * @return true if current session is authenticated
     */
    boolean isAuthenticated(HttpSession session);

    /**
     * Invalidate current session and assertion
     * @param session session to invalidate
     * @param assertion assertion to invalidate
     *
     */
    void logout(HttpSession session, AssertionWrapper assertion);

    /**
     * Clean stored ids and sessions.
     *
     * @param maxInactiveIntervalSeconds Milliseconds to store session, before it should be invalidated.
     */
    void cleanup(long maxInactiveIntervalSeconds);
}
