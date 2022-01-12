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
package dk.gov.oio.saml.session.inmemory;

import dk.gov.oio.saml.audit.AuditService;
import dk.gov.oio.saml.service.OIOSAML3Service;
import dk.gov.oio.saml.session.AssertionWrapper;
import dk.gov.oio.saml.session.AuthnRequestWrapper;
import dk.gov.oio.saml.session.LogoutRequestWrapper;
import dk.gov.oio.saml.session.SessionHandler;
import dk.gov.oio.saml.util.InternalException;
import dk.gov.oio.saml.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpSession;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentSkipListSet;

public class InMemorySessionHandler implements SessionHandler {
    private static final Logger log = LoggerFactory.getLogger(InMemorySessionHandler.class);

    private int sessionHandlerNumTrackedSessionIds;

    private final Map<String, TimeOutWrapper<AuthnRequestWrapper>> authnRequests = new ConcurrentHashMap<String, TimeOutWrapper<AuthnRequestWrapper>>();
    private final Map<String, TimeOutWrapper<AssertionWrapper>> assertions = new ConcurrentHashMap<String, TimeOutWrapper<AssertionWrapper>>();
    private final Map<String, TimeOutWrapper<LogoutRequestWrapper>> logoutRequests = new ConcurrentHashMap<String, TimeOutWrapper<LogoutRequestWrapper>>();

    private final Map<String, TimeOutWrapper<String>> sessionIndexMap = new ConcurrentHashMap<String, TimeOutWrapper<String>>();
    private final ConcurrentSkipListSet<String> usedAssertionIds = new ConcurrentSkipListSet<>();

    public InMemorySessionHandler(int sessionHandlerNumTrackedSessionIds) {
        this.sessionHandlerNumTrackedSessionIds = sessionHandlerNumTrackedSessionIds;
    }

    /**
     * Set AuthnRequest on the current session
     *
     * @param session HTTP session
     * @param request {@link AuthnRequestWrapper}
     */
    @Override
    public void storeAuthnRequest(HttpSession session, AuthnRequestWrapper request) throws InternalException {
        if (null == request || null == request.getId()) {
            log.warn("Ignore AuthRequest with null value or missing ID");
            return;
        }
        AuthnRequestWrapper authnRequest = getAuthnRequest(session);
        if (null != authnRequest) {
            log.debug("AuthRequest '{}' will replace '{}'", request.getId(), authnRequest.getId());
        }
        log.debug("Store AuthRequest '{}'", request.getId());
        authnRequests.put(session.getId(),new TimeOutWrapper<>(request));
    }

    /**
     * Set Assertion on the current session
     *
     * @param session   HTTP session
     * @param assertion {@link AssertionWrapper}
     */
    @Override
    public void storeAssertion(HttpSession session, AssertionWrapper assertion) {
        if (null == assertion || StringUtil.isEmpty(assertion.getID())) {
            log.warn("Ignore Assertion with null value or missing ID");
            return;
        }
        if (StringUtil.isEmpty(assertion.getSessionIndex())) {
            log.info("Assertion '{}' with passive session and missing index", assertion.getID());
        }

        // Replay validation
        if(usedAssertionIds.contains(assertion.getID())) {
            log.error("Assertion '{}' is begin replayed", assertion.getID());
            throw new IllegalArgumentException(String.format("Assertion ID begin replayed: '%s'", assertion.getID()));
        }
        usedAssertionIds.add(assertion.getID());

        // Save assertion
        AssertionWrapper existingAssertion = getAssertion(session);
        if (null != existingAssertion) {
            if (assertion.isReplayOf(existingAssertion)) {
                log.debug("Assertion '{}' is being replayed", assertion.getID(), existingAssertion.getID());
                throw new IllegalArgumentException(String.format("Assertion with id '%s' and session index '%s' is already registered", assertion.getID(), assertion.getSessionIndex()));
            }

            log.debug("Assertion '{}' will replace '{}'", assertion.getID(), existingAssertion.getID());
            sessionIndexMap.remove(StringUtil.defaultIfEmpty(existingAssertion.getSessionIndex(), existingAssertion.getID()));
        }

        log.debug("Store Assertion '{}'", assertion.getID());
        assertions.put(session.getId(), new TimeOutWrapper<>(assertion));
        sessionIndexMap.put(StringUtil.defaultIfEmpty(assertion.getSessionIndex(), assertion.getID()), new TimeOutWrapper<>(session.getId()));
    }

    /**
     * Set LogoutRequest on the current session
     *
     * @param session HTTP session
     * @param request {@link LogoutRequestWrapper}
     */
    @Override
    public void storeLogoutRequest(HttpSession session, LogoutRequestWrapper request) {
        if (null == request || null == request.getID()) {
            log.warn("Ignore LogoutRequest with null value or missing ID");
            return;
        }
        LogoutRequestWrapper logoutRequest = getLogoutRequest(session);
        if (null != logoutRequest) {
            log.debug("LogoutRequest '{}' will replace '{}'", request.getID(), logoutRequest.getID());
        }
        log.debug("Store LogoutRequest '{}'", request.getID());
        logoutRequests.put(session.getId(),new TimeOutWrapper<>(request));
    }

    /**
     * Get AuthnRequest from the current session
     *
     * @param session HTTP session
     * @return AuthnRequest from current session
     */
    @Override
    public AuthnRequestWrapper getAuthnRequest(HttpSession session) {
        TimeOutWrapper<AuthnRequestWrapper> wrapperTimeOutWrapper = authnRequests.get(session.getId());
        if (null == wrapperTimeOutWrapper || null == wrapperTimeOutWrapper.getObject()) {
            return null;
        }
        log.debug("Get AuthnRequest from the current session '{}'", session.getId());
        wrapperTimeOutWrapper.setAccesstime();

        return wrapperTimeOutWrapper.getObject();
    }

    /**
     * Get Assertion from the current session
     *
     * @param session HTTP session
     * @return Assertion from current session
     */
    @Override
    public AssertionWrapper getAssertion(HttpSession session) {
        TimeOutWrapper<AssertionWrapper> wrapperTimeOutWrapper = assertions.get(session.getId());
        if (null == wrapperTimeOutWrapper || null == wrapperTimeOutWrapper.getObject()) {
            return null;
        }
        log.debug("Get AssertionWrapper from the current session '{}'", session.getId());
        wrapperTimeOutWrapper.setAccesstime();

        return wrapperTimeOutWrapper.getObject();
    }

    /**
     * Get Assertion matching sessionIndex
     *
     * @param sessionIndex OPENSAML sessionIndex
     * @return Assertion matching sessionIndex
     */
    @Override
    public AssertionWrapper getAssertion(String sessionIndex) {
        if (null == sessionIndex || !sessionIndexMap.containsKey(sessionIndex)) {
            log.debug("Session index '{}' is missing",sessionIndex);
            return null;
        }
        String sessionId = sessionIndexMap.get(sessionIndex).getObject();

        TimeOutWrapper<AssertionWrapper> wrapperTimeOutWrapper = assertions.get(sessionId);
        if (null == wrapperTimeOutWrapper || null == wrapperTimeOutWrapper.getObject()) {
            return null;
        }
        log.debug("Get AssertionWrapper from the session '{}' with sessionIndex '{}'", sessionId, sessionIndex);
        wrapperTimeOutWrapper.setAccesstime();

        return wrapperTimeOutWrapper.getObject();
    }

    /**
     * Get LogoutRequest from current session
     *
     * @param session HTTP session
     * @return LogoutRequest from current session
     */
    @Override
    public LogoutRequestWrapper getLogoutRequest(HttpSession session) {
        TimeOutWrapper<LogoutRequestWrapper> wrapperTimeOutWrapper = logoutRequests.get(session.getId());
        if (null == wrapperTimeOutWrapper || null == wrapperTimeOutWrapper.getObject()) {
            return null;
        }
        log.debug("Get LogoutRequestWrapper from the current session '{}'", session.getId());
        wrapperTimeOutWrapper.setAccesstime();

        return wrapperTimeOutWrapper.getObject();
    }

    /**
     * Get OIOSAML session ID for current session
     *
     * @param session HTTP session
     * @return OIOSAML session ID (for audit logging)
     */
    @Override
    public String getSessionId(HttpSession session) {
        return session.getId();
    }

    /**
     * Get OIOSAML session ID for session with session index
     *
     * @param sessionIndex Session index to lookup session ID for
     * @return OIOSAML session ID (for audit logging)
     */
    @Override
    public String getSessionId(String sessionIndex) {
        if (StringUtil.isEmpty(sessionIndex) || !sessionIndexMap.containsKey(sessionIndex)) {
            return null;
        }
        return sessionIndexMap.get(sessionIndex).getObject();
    }

    /**
     * Invalidate current OIOSAML session
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

    private void logout(String sessionId) {
        log.debug("Invalidate OIOSAML session '{}'", sessionId);

        if (StringUtil.isEmpty(sessionId) || !assertions.containsKey(sessionId)) {
            return;
        }

        TimeOutWrapper<AssertionWrapper> wrapperTimeOutWrapper = assertions.get(sessionId);
        sessionIndexMap.remove(wrapperTimeOutWrapper.getObject().getSessionIndex());
        assertions.remove(sessionId);
    }

    /**
     * Clean stored ids and sessions.
     *
     * @param maxInactiveIntervalSeconds Milliseconds to store session, before it should be invalidated.
     */
    @Override
    public void cleanup(long maxInactiveIntervalSeconds) {
        // Trim usedAssertionIds to size with sessionHandlerNumTrackedSessionIds
        while (!usedAssertionIds.isEmpty() && usedAssertionIds.size() > sessionHandlerNumTrackedSessionIds) {
            usedAssertionIds.remove(usedAssertionIds.pollFirst());
        }
        cleanup(sessionIndexMap, maxInactiveIntervalSeconds, "SessionIndexMap");
        cleanup(assertions, maxInactiveIntervalSeconds, "Assertions");
        cleanup(authnRequests, maxInactiveIntervalSeconds, "AuthnRequests");
        cleanup(logoutRequests, maxInactiveIntervalSeconds, "LogoutRequests");
    }

    private <E, T> void cleanup(Map<E, TimeOutWrapper<T>> map, long cleanupDelay, String msg) {
        log.debug("Running cleanup timer on {}", map);
        for (Object key : map.keySet()) {
            TimeOutWrapper<T> tow = map.get(key);
            if (tow.isExpired(cleanupDelay)) {
                log.debug("Expiring {}", tow);
                if (tow.getObject() instanceof AssertionWrapper) {
                    OIOSAML3Service.getAuditService().auditLog(new AuditService
                            .Builder()
                            .withAuthnAttribute("ACTION", "TIMEOUT")
                            .withAuthnAttribute("DESCRIPTION", "SessionDestroyed")
                            .withAuthnAttribute("SESSION_ID", String.valueOf(key))
                            .withAuthnAttribute("ASSERTION_ID", ((AssertionWrapper) tow.getObject()).getID())
                            .withAuthnAttribute("SUBJECT_NAME_ID", ((AssertionWrapper) tow.getObject()).getSubjectNameId()));
                }
                map.remove(key);
            }
        }
    }

}
