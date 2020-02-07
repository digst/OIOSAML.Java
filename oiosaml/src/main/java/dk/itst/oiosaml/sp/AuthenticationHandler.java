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
package dk.itst.oiosaml.sp;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Use this interface to receive notifications about user authentications. 
 * 
 * @author Joakim Recht
 *
 */
public interface AuthenticationHandler {
	
	/**
	 * This method is called right after an assertion has been received and validated. It will be called before the user is redirected to the
	 * page originally requested.
	 * 
	 * <p>Throwing a runtime exception from this method will result in the default error page - refer to the oiosaml developer documentation
	 * on how to customize this.</p>
	 * 
	 * @param assertion The assertion received.
	 * @return Return <code>false</code> if processing should fail - ie the user should not be authenticated anyway.
	 * If <code>false</code> is returned, no state will be registered in the session, and processing will be aborted. Any
	 * information to the user should be written manually using the response object.
	 * 
	 */
	public boolean userAuthenticated(UserAssertion assertion, HttpServletRequest request, HttpServletResponse response);

}
