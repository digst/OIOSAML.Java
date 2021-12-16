package dk.gov.oio.saml.session.inmemory;

import dk.gov.oio.saml.session.AssertionWrapper;
import dk.gov.oio.saml.session.AuthnRequestWrapper;
import dk.gov.oio.saml.session.SessionHandler;
import org.opensaml.saml.saml2.core.LogoutRequest;

import javax.servlet.http.HttpSession;

public class InMemorySessionHandler implements SessionHandler {
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
     * Get Assertion from the current session
     *
     * @param session HTTP session
     * @return Assertion from current session
     */
    @Override
    public AssertionWrapper getAssertion(HttpSession session) {
        return null;
    }

    /**
     * Get Assertion matching sessionIndex
     *
     * @param sessionIndex OPENSAML sessionIndex
     * @return Assertion matching sessionIndex
     */
    @Override
    public AssertionWrapper getAssertion(String sessionIndex) {
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

    }
}
