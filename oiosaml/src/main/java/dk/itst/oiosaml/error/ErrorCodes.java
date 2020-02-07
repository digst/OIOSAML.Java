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
 * Feasible error codes to use
 * @author lsteinth
 */
public class ErrorCodes {

	public static final String VERSION = "$Id: ErrorCodes.java 2829 2008-05-13 12:11:31Z jre $";
    public static final ErrorCode RUNTIME_EXCEPTION = new ErrorCode("RUNTIME_EXCEPTION");
    public static final ErrorCode REMOTE_EXCEPTION = new ErrorCode("REMOTE_EXCEPTION");
    public static final ErrorCode WRAPPED_EXCEPTION = new ErrorCode("WRAPPED_EXCEPTION");
    public static final ErrorCode SERIALIZED_EXCEPTION = new ErrorCode("SERIALIZED_EXCEPTION");
    public static final ErrorCode OBJECT_NOT_FOUND = new ErrorCode("OBJECT_NOT_FOUND");
    public static final ErrorCode STARTUP_EXCEPTION = new ErrorCode("STARTUP_EXCEPTION");

    public static class ErrorCode {
        private String value;

        /**
         * Create a new <code>ErrorCode</code>
         * @param value The value of the error
         */
        public ErrorCode(String value) {
            this.value = value;
        }

        /**
         * @return The value of the error code
         */
        public String getValue() {
            return value;
        }
    }

}
