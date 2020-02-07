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
package dk.itst.oiosaml.sp.service;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import dk.itst.oiosaml.logging.Logger;
import dk.itst.oiosaml.logging.LoggerFactory;
import org.apache.commons.io.IOUtils;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.security.credential.Credential;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.error.Layer;
import dk.itst.oiosaml.error.WrappedException;
import dk.itst.oiosaml.logging.Audit;
import dk.itst.oiosaml.logging.Operation;
import dk.itst.oiosaml.sp.metadata.IdpMetadata.Metadata;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.model.OIOLogoutRequest;
import dk.itst.oiosaml.sp.model.OIOLogoutResponse;
import dk.itst.oiosaml.sp.util.LogoutRequestValidationException;

/**
 * Servlet for receiving a &lt;LogoutRequest&gt; sent from the Login Site by SOAP.
 * 
 * @author Joakim Recht, Trifork A/S
 * @author Rolf Njor Jensen, Trifork A/S
 */
public class LogoutServiceSOAPHandler implements SAMLHandler {
	private static final Logger log = LoggerFactory.getLogger(LogoutServiceSOAPHandler.class);

	private static OIOLogoutRequest extractRequest(HttpServletRequest request) throws IOException {
		InputStream is = request.getInputStream();
		
		// Unpack the <LogoutRequest>
		String xml = IOUtils.toString(is, "UTF-8");
		XMLObject xmlObject = SAMLUtil.unmarshallElementFromString(xml);

		if (log.isDebugEnabled()) log.debug("Request..:" + xml);

		if (xmlObject != null && xmlObject instanceof Envelope) {
			Envelope envelope = (Envelope) xmlObject;
			Body body = envelope.getBody();
			xmlObject = (XMLObject) body.getUnknownXMLObjects().get(0);
			if (xmlObject != null && xmlObject instanceof LogoutRequest) {
				LogoutRequest logoutRequest = (LogoutRequest) xmlObject;
				return new OIOLogoutRequest(logoutRequest);
			}
		}
		throw new RuntimeException("SOAP request did not contain a LogoutRequest on the body");
	}
	/**
	 * Receive and handle a &lt;LogoutRequest&gt; from the Login Site
	 * @throws IOException 
	 */
	public void handlePost(RequestContext ctx) throws ServletException, IOException {
		String statusCode = StatusCode.SUCCESS_URI;
		String consent = null;

		OIOLogoutRequest logoutRequest = extractRequest(ctx.getRequest());
		Audit.log(Operation.LOGOUT_SOAP, false, logoutRequest.getID(), logoutRequest.toXML());
		try {
			
			String sessionIndex = logoutRequest.getSessionIndex();
			String sessionId = ctx.getSessionHandler().getRelatedSessionId(sessionIndex);
			
			OIOAssertion assertion = ctx.getSessionHandler().getAssertion(sessionId);
			String idpEntityId = null;
			if (assertion != null) {
				idpEntityId = assertion.getIssuer();
			}
			if (idpEntityId == null) {
				log.warn("LogoutRequest received over SOAP for unknown user");
				statusCode = StatusCode.NO_SUPPORTED_IDP_URI;
			} else {
				try {
					Metadata metadata = ctx.getIdpMetadata().getMetadata(idpEntityId);

					logoutRequest.validateRequest(null, null, metadata.getPublicKeys(), ctx.getSpMetadata().getSingleLogoutServiceSOAPLocation(), metadata.getEntityID());
					ctx.getSessionHandler().logOut(sessionId);
					
					Audit.log(Operation.LOGOUT, assertion.getSubjectNameIDValue());
				} catch (LogoutRequestValidationException e) {
					consent = e.getMessage();
					statusCode = StatusCode.AUTHN_FAILED_URI;
				}
			}
		} catch (Throwable t) {
			statusCode = StatusCode.AUTHN_FAILED_URI;
			consent = t instanceof WrappedException ? t.getCause().getMessage() : t.getMessage();
			Audit.logError(Operation.LOGOUT_SOAP, false, logoutRequest.getID(), t);
		}

		if (log.isDebugEnabled()) log.debug("Logout status: " + statusCode + ", message: " + consent);

		OIOLogoutResponse logoutResponse = OIOLogoutResponse.fromRequest(logoutRequest, statusCode, consent, ctx.getSpMetadata().getEntityID(), null);
		returnResponse(ctx.getResponse(), logoutResponse, ctx.getCredential());
		Audit.log(Operation.LOGOUT_SOAP, true, logoutRequest.getID(), logoutResponse.toXML());
	}

	public void handleGet(RequestContext ctx) throws IOException {
		String wsdl = ctx.getRequest().getParameter("wsdl");
		HttpServletResponse response = ctx.getResponse();
		if (wsdl != null) {
			try {
				if (log.isDebugEnabled())
					log.debug("Returning wsdl...");
				PrintWriter out = response.getWriter();
				response.setContentType("text/xml");
				response.setCharacterEncoding("UTF-8");
				InputStream in = LogoutServiceSOAPHandler.class.getResourceAsStream("/SAML2LogoutService.wsdl");
				IOUtils.copy(in, out);

				in.close();
				out.flush();
				return;
			} catch (IOException e) {
				throw new WrappedException(Layer.CLIENT, e);
			}
		}

		response.sendError(HttpServletResponse.SC_PRECONDITION_FAILED, "No argument wsdl on get request. Use POST for SOAP requests.");
	}

	/**
	 * Return the &lt;LogoutResponse&gt; to the caller
	 * 
	 * @param response
	 *            The {@link HttpServletResponse}
	 * @param logoutResponse
	 *            The &lt;LogoutResponse&gt; to return to the caller
	 */
	private static void returnResponse(HttpServletResponse response,
			OIOLogoutResponse logoutResponse, Credential credential) {
		logoutResponse.sign(credential);
		
		// Build output...
		String envelope = logoutResponse.toSoapEnvelope();

		if (log.isDebugEnabled())
			log.debug("Response..: " + envelope);

		byte[] b;
		try {
			b = envelope.getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new WrappedException(Layer.CLIENT, e);
		}
		response.setContentLength(b.length);
		response.setCharacterEncoding("UTF-8");
		response.setContentType("text/xml");
		response.setStatus(HttpServletResponse.SC_OK);
		try {
			response.getOutputStream().write(b);
		} catch (IOException e) {
			throw new WrappedException(Layer.CLIENT, e);
		}
	}

}
