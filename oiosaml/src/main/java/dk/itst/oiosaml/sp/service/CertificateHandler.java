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
package dk.itst.oiosaml.sp.service;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.cert.CertificateEncodingException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.util.Base64;

public class CertificateHandler implements SAMLHandler {

	public void handleGet(RequestContext context) throws ServletException, IOException {
		X509Credential cred = (X509Credential) context.getCredential();
		try {
			String cert = Base64.encodeBytes(cred.getEntityCertificate().getEncoded());
			
			HttpServletResponse res = context.getResponse();
			res.setContentType("text/plain");
			PrintWriter pw = res.getWriter();
			pw.println("-----BEGIN CERTIFICATE-----");
			pw.println(cert);
			pw.println("-----END CERTIFICATE-----");
			pw.close();
		} catch (CertificateEncodingException e) {
			throw new ServletException(e);
		}
	}

	public void handlePost(RequestContext context) throws ServletException, IOException {
		throw new UnsupportedOperationException();
	}

}
