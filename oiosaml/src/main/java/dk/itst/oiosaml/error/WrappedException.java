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
package dk.itst.oiosaml.error;


/**
 * Wraps an exception, which a program cannot be expected to handle (e.g. certain flavors of
 * SQLException, Error, RuntimeException, ...). This exception type is
 * used as a "catch all" mechanism, when there is no need to specify the exact failure any
 * further. The WrappedException is a RuntimeException and can be thrown freely.
 */
public class WrappedException extends UnrecoverableException {

	public static final String VERSION = "$Id: WrappedException.java 2847 2008-05-14 13:37:36Z rolf $";
	private static final long serialVersionUID = -4215933609877540662L;

	/**
	 * @see UnrecoverableException#UnrecoverableException(ErrorCodes.ErrorCode, Layer, String)
	 */
	public WrappedException(Layer layer, Throwable cause) {
        super(ErrorCodes.WRAPPED_EXCEPTION, layer, "Wrapped" , cause);
    }
}
