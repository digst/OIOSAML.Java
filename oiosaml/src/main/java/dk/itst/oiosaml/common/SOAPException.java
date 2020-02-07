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
package dk.itst.oiosaml.common;

import java.io.IOException;
import java.util.List;

import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.soap.soap11.Fault;
import org.opensaml.xml.XMLObject;


/**
 * Representation of a SOAP Fault.
 * 
 * @author recht
 *
 */
public class SOAPException extends IOException {
	private static final long serialVersionUID = 6684189535343316988L;
	private final String response;
	private Envelope envelope;

	public SOAPException(int responseCode, String response) {
		super("Server returned error response: " + responseCode);
		this.response = response;
		
		try {
			envelope = (Envelope) SAMLUtil.unmarshallElementFromString(response);
		} catch (Exception e) {}
	}

	/**
	 * Get the SOAP Envelope.
	 * @return
	 */
	public Envelope getEnvelope() {
		return envelope;
	}
	
	/**
	 * Get the complete response from the server as a string.
	 * */
	public String getResponse() {
		return response;
	}

	/**
	 * Get the SOAP Fault object.
	 * @return Can return <code>null</code> if the response did not contain a fault element.
	 */
	public Fault getFault() {
		if (envelope == null) return null; 
		List<XMLObject> faults = envelope.getBody().getUnknownXMLObjects(Fault.DEFAULT_ELEMENT_NAME);
		if (faults.isEmpty()) return null;

		return (Fault) faults.get(0);
	}

}
