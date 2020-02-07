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
package dk.itst.oiosaml.sp.service.util;

import java.io.IOException;

import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.XMLObject;

import dk.itst.oiosaml.common.SOAPException;
import dk.itst.oiosaml.sp.model.OIOSamlObject;

public interface SOAPClient {
	public Envelope wsCall(XMLObject obj, String location, String username, String password, boolean ignoreCertPath) throws IOException;
	public XMLObject wsCall(OIOSamlObject obj, String location, String username, String password, boolean ignoreCertPath) throws IOException;

	/**
	 * Execute a raw request against a SOAP service.
	 * @param location HTTP Endpoint for the service.
	 * @param username Username for http basic auth. Can be <code>null</code>, in which case basic auth is disabled.
	 * @param password Basic auth password.
	 * @param ignoreCertPath Set to <code>true</code> to ignore certificate path errors on ssl connections.
	 * @param xml Complete SOAP Envelope as string.
	 * @param soapAction SOAP Action to invoke.
	 * @return The response envelope if the server returned 200 OK. An exeption is thrown in all other cases.
	 * @throws IOException If a generic IO exception occurred, for example if the connection failed.
	 * @throws SOAPException If the server returned anything but 200 OK.
	 */
	public Envelope wsCall(String location, String username, String password, boolean ignoreCertPath, String xml, String soapAction) throws IOException, SOAPException;
}

