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
 * created by Trifork A/S are Copyright (C) 2008 Danish National IT 
 * and Telecom Agency (http://www.itst.dk). All Rights Reserved.
 * 
 * Contributor(s):
 *   Joakim Recht <jre@trifork.com>
 *   Rolf Njor Jensen <rolf@trifork.com>
 *
 */
package dk.itst.oiosaml.sp;

/**
 * ThreadLocal holder for the current user assertion.
 * 
 * Use {@link #get()} to retrieve the assertion from the application layer if there is no access to the session.
 *  
 * @author recht
 *
 */
public  final class UserAssertionHolder {
	private static final ThreadLocal<UserAssertion> assertion = new ThreadLocal<UserAssertion>();

	/**
	 * Get the current user assertion. Will return <code>null</code> if the user is not authenticated.
	 */
	public static UserAssertion get() {
		return assertion.get();
	}
	
	public static void set(UserAssertion assertion) {
		UserAssertionHolder.assertion.set(assertion);
	}
}
