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
package dk.itst.oiosaml.sp.model;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PublicKey;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import javax.servlet.http.HttpServletRequest;

import dk.itst.oiosaml.logging.Logger;
import dk.itst.oiosaml.logging.LoggerFactory;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.binding.decoding.HTTPPostDecoder;
import org.opensaml.saml2.binding.decoding.HTTPRedirectDeflateDecoder;
import org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.util.URLBuilder;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.Pair;
import org.opensaml.xml.util.XMLHelper;
import org.opensaml.xml.validation.ValidationException;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.error.Layer;
import dk.itst.oiosaml.error.WrappedException;
import dk.itst.oiosaml.sp.service.util.Constants;
import dk.itst.oiosaml.sp.service.util.Utils;

public class OIOLogoutResponse extends OIOAbstractResponse {
	private static final Logger log = LoggerFactory.getLogger(OIOLogoutResponse.class);

	private final LogoutResponse response;

	public OIOLogoutResponse(LogoutResponse response) {
		super(response);
		this.response = response;
	}
	
	public static OIOLogoutResponse fromRequest(OIOLogoutRequest request, String statusCode, String consent, String entityId, String destination) {
		LogoutResponse logoutResponse = SAMLUtil.buildXMLObject(LogoutResponse.class);

		logoutResponse.setID(Utils.generateUUID());
		logoutResponse.setIssueInstant(new DateTime(DateTimeZone.UTC));
		logoutResponse.setVersion(SAMLVersion.VERSION_20);
		logoutResponse.setStatus(SAMLUtil.createStatus(statusCode != null ? statusCode : StatusCode.SUCCESS_URI));
		
		if (request != null) {
			logoutResponse.setInResponseTo(request.getID());
		}
		logoutResponse.setIssuer(SAMLUtil.createIssuer(entityId));
		logoutResponse.setDestination(destination);
		if (consent != null) {
			logoutResponse.setConsent(consent);
		}
		if (statusCode != null && !StatusCode.SUCCESS_URI.equals(statusCode)) {
			log.error("Invalid <LogoutRequest>: " + consent);
		}
		try {
			if (log.isDebugEnabled()) log.debug("Validate the logoutResponse...");
			logoutResponse.validate(true);
			if (log.isDebugEnabled()) log.debug("...OK");
		} catch (ValidationException e) {
			throw new WrappedException(Layer.CLIENT, e);
		}

		return new OIOLogoutResponse(logoutResponse);
	}

	public static OIOLogoutResponse fromPostRequest(HttpServletRequest request) {
        BasicSAMLMessageContext<LogoutResponse, ?, ?> messageContext = new BasicSAMLMessageContext<LogoutResponse, SAMLObject, SAMLObject>();
        messageContext.setInboundMessageTransport(new HttpServletRequestAdapter(request));

        try {
        	HTTPPostDecoder decoder = new HTTPPostDecoder();
            decoder.decode(messageContext);
        } catch (MessageDecodingException e) {
            throw new WrappedException(Layer.CLIENT, e);
        } catch (SecurityException e) {
            throw new WrappedException(Layer.CLIENT, e);
        }
        
		LogoutResponse logoutResponse = messageContext.getInboundSAMLMessage();
		OIOLogoutResponse res = new OIOLogoutResponse(logoutResponse);
		if (log.isDebugEnabled()) {
			log.debug("Received response: " + res.toXML());
		}
		
		return res;
	}
	
	public static OIOLogoutResponse fromHttpRedirect(HttpServletRequest request) {
		BasicSAMLMessageContext<LogoutResponse, ?, ?> messageContext = new BasicSAMLMessageContext<LogoutResponse, SAMLObject, SAMLObject>();
		messageContext.setInboundMessageTransport(new HttpServletRequestAdapter(request));

		try {
			HTTPRedirectDeflateDecoder decoder = new HTTPRedirectDeflateDecoder();
			decoder.decode(messageContext);
		} catch (MessageDecodingException e) {
			throw new WrappedException(Layer.CLIENT, e);
		} catch (SecurityException e) {
			throw new WrappedException(Layer.CLIENT, e);
		}

		LogoutResponse logoutResponse = messageContext.getInboundSAMLMessage();
		OIOLogoutResponse res = new OIOLogoutResponse(logoutResponse);
		if (log.isDebugEnabled()) {
			log.debug("Received response: " + res.toXML());
		}
		
		return res;
	}
	
	/**
	 * @param relayState
	 *            The relayState to be included with the &lt;LogoutResponse&gt;
	 * @return A URL containing an &lt;LogoutResponse&gt; as a response to a
	 *         &lt;LogoutRequest&gt;
	 */
	public String getRedirectURL(Credential signingCredential, String relayState) {
		Encoder enc = new Encoder();

		// Build the parameters for the response
		if (log.isDebugEnabled())
			log.debug("Setting RelayState..:" + relayState);

		try {
			return buildRedirectURL(enc.deflateAndBase64Encode(response), relayState, signingCredential);
		} catch (MessageEncodingException e) {
			throw new WrappedException(Layer.CLIENT, e);
		}
	}

	/**
	 * @see org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder#buildRedirectURL(org.opensaml.common.binding.SAMLMessageContext,
	 *      java.lang.String, java.lang.String)
	 */
	private String buildRedirectURL(String message, String relayState, Credential signingCredential) throws MessageEncodingException {

		if (log.isDebugEnabled())
			log.debug("Building URL to redirect client to: " + response.getDestination());

		URLBuilder urlBuilder = new URLBuilder(response.getDestination());

		List<Pair<String, String>> queryParams = urlBuilder.getQueryParams();
		queryParams.clear();
		queryParams.add(new Pair<String, String>(Constants.SAML_SAMLRESPONSE, message));

		// Quick patch made because Microsoft ADFS cannot handle an empty relaystate param
		// Beware that ADFS sends an errormessage, but is not logging the user out, so the errormessage SHOULD tell the end users to close their browsers
		if(relayState != null) {
	        queryParams.add(new Pair<String, String>(Constants.SAML_RELAYSTATE, relayState));
		}

		Encoder enc = new Encoder();
		if (signingCredential != null) {
			queryParams.add(new Pair<String, String>(Constants.SAML_SIGALG, enc.getSignatureAlgorithmURI(signingCredential, null)));
			String sigMaterial = urlBuilder.buildQueryString();

			queryParams.add(new Pair<String, String>(Constants.SAML_SIGNATURE,
					enc.generateSignature(signingCredential, enc.getSignatureAlgorithmURI(signingCredential, null), sigMaterial)));
		}
		return urlBuilder.buildURL();
	}
	
	public void validate(String requestId, String expectedDestination) throws dk.itst.oiosaml.sp.model.validation.ValidationException {
		try {
			response.validate(true);
		} catch (ValidationException e) {
			log.error("Unable to validate message", e);
			throw new dk.itst.oiosaml.sp.model.validation.ValidationException(e);
		}
		validateResponse(requestId, expectedDestination, false);
	}
	
	public void validate(String requestId, String expectedDestination, String signature, String queryString, final PublicKey key) {
        validate(requestId, expectedDestination, signature, queryString, Collections.singletonList(key));
	}
	
	public void validate(String requestId, String expectedDestination, String signature, String queryString, Collection<PublicKey> keys) {
		validate(requestId, expectedDestination);
		
		boolean valid = false;
		for (PublicKey key : keys) {
			if (Utils.verifySignature(signature, queryString, Constants.SAML_SAMLRESPONSE, key)) {
				valid = true;
			}
		}
		if (!valid) {
			throw new dk.itst.oiosaml.sp.model.validation.ValidationException("Invalid signature");
		} else if (log.isDebugEnabled()) {
			log.debug("...signature OK");
		}
	}
	
	/**
	 * This method will validate the internal xmldsig signature, as well as run validate()
	 */
	public void validate(String requestId, String expectedDestination, Collection<PublicKey> keys) {
		validate(requestId, expectedDestination);
		
		boolean valid = false;
		for (PublicKey key : keys) {
			if (verifySignature(key)) {
				valid = true;
			}
		}

		if (!valid) {
			throw new dk.itst.oiosaml.sp.model.validation.ValidationException("Invalid signature");
		}
		else if (log.isDebugEnabled()) {
			log.debug("...signature OK");
		}
	}
	
	protected static class Encoder extends HTTPRedirectDeflateEncoder {

        @Override
		public String deflateAndBase64Encode(SAMLObject obj) throws MessageEncodingException {
            String messageStr = XMLHelper.nodeToString(marshallMessage(obj));

            ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
            Deflater deflater = new Deflater(Deflater.DEFLATED, true);
            DeflaterOutputStream deflaterStream = new DeflaterOutputStream(bytesOut, deflater);
            try {
				deflaterStream.write(messageStr.getBytes("UTF-8"));
				deflaterStream.finish();
			} catch (IOException e) {
				throw new RuntimeException("Unable to deflate message", e);
			}

            return Base64.encodeBytes(bytesOut.toByteArray(), Base64.DONT_BREAK_LINES);
		}

        @Override
        protected String generateSignature(Credential signingCredential, String algorithmURI, String queryString)
                throws MessageEncodingException {
            return super.generateSignature(signingCredential, algorithmURI, queryString);
        }

        @Override
        protected String getSignatureAlgorithmURI(Credential credential, SecurityConfiguration config)
                throws MessageEncodingException {
            return super.getSignatureAlgorithmURI(credential, config);
        }
	
	}

}
