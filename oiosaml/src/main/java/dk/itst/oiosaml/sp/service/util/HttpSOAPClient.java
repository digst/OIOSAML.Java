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
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;

import dk.itst.oiosaml.logging.Logger;
import dk.itst.oiosaml.logging.LoggerFactory;
import org.apache.commons.io.IOUtils;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.soap.soap11.Fault;
import org.opensaml.ws.soap.util.SOAPConstants;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.common.SOAPException;
import dk.itst.oiosaml.sp.model.OIOSamlObject;

public class HttpSOAPClient implements SOAPClient {
	private static final String START_SOAP_ENVELOPE = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">" + "<soapenv:Header/><soapenv:Body>";
	private static final String END_SOAP_ENVELOPE = "</soapenv:Body></soapenv:Envelope>";
	private static final Logger log = LoggerFactory.getLogger(HttpSOAPClient.class);

	public XMLObject wsCall(OIOSamlObject obj, String location, String username, String password, boolean ignoreCertPath) throws IOException {
		return wsCall(location, username, password, ignoreCertPath, obj.toSoapEnvelope(), "http://www.oasis-open.org/committees/security").getBody().getUnknownXMLObjects().get(0);
	}
	
	public Envelope wsCall(XMLObject obj, String location, String username, String password, boolean ignoreCertPath) throws IOException {
		String xml = XMLHelper.nodeToString(SAMLUtil.marshallObject(obj));
		xml = START_SOAP_ENVELOPE + xml.substring(xml.indexOf("?>") + 2) + END_SOAP_ENVELOPE;
		return wsCall(location, username, password, ignoreCertPath, xml, "http://www.oasis-open.org/committees/security");
	}

	public Envelope wsCall(String location, String username, String password, boolean ignoreCertPath, String xml, String soapAction) throws IOException, SOAPException {
		URI serviceLocation;
		try {
			serviceLocation = new URI(location);
		} catch (URISyntaxException e) {
			throw new IOException("Invalid uri for artifact resolve: " + location);
		}
		if (log.isDebugEnabled()) log.debug("serviceLocation..:" + serviceLocation);
		if (log.isDebugEnabled()) log.debug("SOAP Request: " + xml);

		HttpURLConnection c = (HttpURLConnection) serviceLocation.toURL().openConnection();
		if (c instanceof HttpsURLConnection) {
			HttpsURLConnection sc = (HttpsURLConnection) c;
			
			if (ignoreCertPath) {
				sc.setSSLSocketFactory(new DummySSLSocketFactory());
				sc.setHostnameVerifier(new HostnameVerifier() {
					public boolean verify(String hostname, SSLSession session) {
						return true;
					}
				});
			}
		}
		c.setAllowUserInteraction(false);
		c.setDoInput(true);
		c.setDoOutput(true);
		c.setFixedLengthStreamingMode(xml.getBytes("UTF-8").length);
		c.setRequestMethod("POST");
		c.setReadTimeout(20000);
		c.setConnectTimeout(30000);
		
		addContentTypeHeader(xml, c);
		c.addRequestProperty("SOAPAction",  "\"" + (soapAction == null ? "" : soapAction) + "\"");
		
		if (username != null && password != null) {
			c.addRequestProperty("Authorization", "Basic " + Base64.encodeBytes((username + ":" + password).getBytes(), Base64.DONT_BREAK_LINES));
		}
		OutputStream outputStream = c.getOutputStream();
		IOUtils.write(xml, outputStream, "UTF-8");
		outputStream.flush();
		outputStream.close();
		
		if (c.getResponseCode() == 200) {
			InputStream inputStream = c.getInputStream();
			String result = IOUtils.toString(inputStream, "UTF-8");
			inputStream.close();
			
			if (log.isDebugEnabled()) log.debug("Server SOAP response: " + result);
			XMLObject res = SAMLUtil.unmarshallElementFromString(result);
			
			Envelope envelope = (Envelope) res;
			if (SAMLUtil.getFirstElement(envelope.getBody(), Fault.class) != null) {
				log.warn("Result has soap11:Fault, but server returned 200 OK. Treating as error, please fix the server");
				throw new SOAPException(c.getResponseCode(), result);
			}
			return envelope;
		}
		log.debug("Response code: " + c.getResponseCode());
		
		InputStream inputStream = c.getErrorStream();
		String result = IOUtils.toString(inputStream, "UTF-8");
		inputStream.close();
		
		if (log.isDebugEnabled()) log.debug("Server SOAP fault: " + result);
		
		throw new SOAPException(c.getResponseCode(), result);
	}

	private static void addContentTypeHeader(String xml, HttpURLConnection c) {
		String soapVersion = Utils.getSoapVersion(xml);
		if (SOAPConstants.SOAP11_NS.equals(soapVersion)) {
			c.addRequestProperty("Content-Type", "text/xml; charset=utf-8");
		} else if (SOAPConstants.SOAP12_NS.equals(soapVersion)){
			c.addRequestProperty("Content-Type", "application/soap+xml; charset=utf-8");
		} else {
			throw new UnsupportedOperationException("SOAP version " + soapVersion + " not supported");
		}
	}
	
}
