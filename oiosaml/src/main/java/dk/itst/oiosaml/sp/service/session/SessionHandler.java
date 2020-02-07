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

import javax.servlet.http.HttpSession;

import org.opensaml.saml2.core.Assertion;

import dk.itst.oiosaml.sp.model.OIOAssertion;

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
	 * Associate an assertion with a given session.
	 * 
	 * @throws IllegalArgumentException If the assertion is being replayed. Implementations must check that the assertion id has not been seen before.
	 */
	public void setAssertion(String sessionId, OIOAssertion assertion) throws IllegalArgumentException;

	
	/**
	 * @return true if the session is logged in and has a non expired assertion,
	 *         false otherwise. 
	 */
	public boolean isLoggedIn(String sessionId);
	
	/**
	 * Mark a given session as it has been logged out by removing it the
	 * assertion from the session.
	 */
	public void logOut(HttpSession session);
	
	/**
	 * Mark a given session as it has been logged out by removing it the associated
	 * assertion
	 * 
	 * @param sessionId
	 */
	public void logOut(String sessionId);
	
	/**
	 * @return The {@link Assertion} associated with the session. <code>null</code> if there is no assertion.
	 */
	public OIOAssertion getAssertion(String sessionId);
	
	/**
	 * @param sessionIndex
	 *            The sessionIndex from the assertion
	 * @return The sessionId associated with the sessionIndex in case there is
	 *         one, otherwise null
	 */
	public String getRelatedSessionId(String sessionIndex);
	
	public void registerRequest(String id, String receiverEntityID);
	
	
	/**
	 * Remove a request id from the list of registered request ids and return the registered IdP entity id.
	 * @param id
	 * @throws IllegalArgumentException If the request id is unknown.
	 */
	public String removeEntityIdForRequest(String id) throws IllegalArgumentException;

	/**
	 * Clean stored ids and sessions.
	 * 
	 * @param requestIdsCleanupDelay Milliseconds to store assertion ids for replay prevention.
	 * @param sessionCleanupDelay Milliseconds to store session data before purging (in case logout has not been called).
	 */
	public void cleanup(long requestIdsCleanupDelay, long sessionCleanupDelay);
	
	/**
	 * Set the max number of assertion ids to track for replay protection, and reset the cache.
	 * @param maxNum
	 */
	public void resetReplayProtection(int maxNum);

	/**
	 * Save information about a request.
	 * 
	 * The information saved can be retrieved later on using getRequest to replay the request after the user has been authenticated.
	 * 
	 * @return A unique opaque string, no more than 72 characters long.
	 */
	public String saveRequest(Request request);
		
	/**
	 * Get the request for a state identifier.
	 * 
	 * @param state
	 * @throws IllegalArgumentException If the state identifier is unknown.
	 */
	public Request getRequest(String state) throws IllegalArgumentException;
}
