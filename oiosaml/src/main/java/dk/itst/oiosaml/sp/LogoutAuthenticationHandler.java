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
 * Use this interface to receive notifications about user authentications and logouts. 
 * 
 * @author Joakim Recht
 *
 */
public interface LogoutAuthenticationHandler extends AuthenticationHandler {

	/**
	 * Receive a notification when the user is logged out.
	 * 
	 * Nothing should be written to the response under normal circumstances.
	 * 
	 * The method might be called twice during a SLO, depending on the IdP behavior.
	 */
	public void userLoggedOut(HttpServletRequest request, HttpServletResponse response);
	
}
