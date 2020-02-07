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
 * Exception that is not expected to be recoverable.
 * @author lsteinth
 */
public abstract class UnrecoverableException extends RuntimeException  {

	private static final long serialVersionUID = 8184459972073800325L;
	public static final String VERSION = "$Id: UnrecoverableException.java 2847 2008-05-14 13:37:36Z rolf $";
    private ErrorCodes.ErrorCode errorCode;
    private Layer layer;

    /**
     * Create an unrecoverable exception
     * @param errorCode The {@link ErrorCodes} to associate with the exception
     * @param layer The {@link Layer} to associate with the exception
     * @param internalMessage An additional message
     * @param cause The original exception
     */
    public UnrecoverableException(ErrorCodes.ErrorCode errorCode, Layer layer, String internalMessage, Throwable cause) {
        super(internalMessage, cause);
        this.errorCode = errorCode;
        this.layer = layer;
    }

    /**
     * @see #UnrecoverableException(ErrorCodes.ErrorCode, Layer, String, Throwable)
     */
    public UnrecoverableException(ErrorCodes.ErrorCode errorCode, Layer layer, String internalMessage) {
        this(errorCode, layer, internalMessage,  null);
    }

    /**
     * 
     * @return The {@link ErrorCodes.ErrorCode} associated with the exception
     */
    public ErrorCodes.ErrorCode getErrorCode() {
        return errorCode;
    }

    /**
     * 
     * @return The {@link Layer} associated with the exception
     */
    public Layer getLayer() {
        return layer;
    }
}
