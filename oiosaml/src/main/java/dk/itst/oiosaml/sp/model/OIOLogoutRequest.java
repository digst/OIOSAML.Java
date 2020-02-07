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

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import dk.itst.oiosaml.logging.Logger;
import dk.itst.oiosaml.logging.LoggerFactory;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.binding.decoding.HTTPPostDecoder;
import org.opensaml.saml2.binding.decoding.HTTPRedirectDeflateDecoder;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.SessionIndex;
import org.opensaml.saml2.core.impl.LogoutRequestBuilder;
import org.opensaml.saml2.core.impl.SessionIndexBuilder;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.validation.ValidationException;

import dk.itst.oiosaml.common.OIOSAMLConstants;
import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.error.Layer;
import dk.itst.oiosaml.error.WrappedException;
import dk.itst.oiosaml.sp.model.validation.ClockSkewValidator;
import dk.itst.oiosaml.sp.service.session.SessionHandler;
import dk.itst.oiosaml.sp.service.util.Constants;
import dk.itst.oiosaml.sp.service.util.Utils;
import dk.itst.oiosaml.sp.util.LogoutRequestValidationException;

public class OIOLogoutRequest extends OIORequest {
	private static final Logger log = LoggerFactory.getLogger(OIOLogoutRequest.class);

	private final LogoutRequest request;

	public OIOLogoutRequest(LogoutRequest request) {
		super(request);
		this.request = request;
	}
	
	/**
	 * Extract a LogoutRequest from a HTTP redirect request. 
	 * 
	 * @return The extracted request. Never <code>null</code>.
	 * @throws WrappedException If the extraction fails.
	 */
	public static OIOLogoutRequest fromRedirectRequest(HttpServletRequest request) {
		BasicSAMLMessageContext<LogoutRequest, ?, ?> messageContext = getMessageContextFromRequest(request);

		HTTPRedirectDeflateDecoder decoder = new HTTPRedirectDeflateDecoder();

		try {
			decoder.decode(messageContext);
		} catch (MessageDecodingException e) {
			throw new WrappedException(Layer.CLIENT, e);
		} catch (SecurityException e) {
			throw new WrappedException(Layer.CLIENT, e);
		}
		
		return new OIOLogoutRequest(messageContext.getInboundSAMLMessage());
	}
	
	public static OIOLogoutRequest fromPostRequest(HttpServletRequest request) {
        BasicSAMLMessageContext<LogoutRequest, ?, ?> messageContext = getMessageContextFromRequest(request);

        HTTPPostDecoder decoder = new HTTPPostDecoder();
        
        try {
            decoder.decode(messageContext);
        } catch (MessageDecodingException e) {
            throw new WrappedException(Layer.CLIENT, e);
        } catch (SecurityException e) {
            throw new WrappedException(Layer.CLIENT, e);
        }
        
        return new OIOLogoutRequest(messageContext.getInboundSAMLMessage());
	}

    private static BasicSAMLMessageContext<LogoutRequest, ?, ?> getMessageContextFromRequest(HttpServletRequest request) {
        // Unpack the <LogoutRequest> from the request
        BasicSAMLMessageContext<LogoutRequest, ?, ?> messageContext = new BasicSAMLMessageContext<LogoutRequest, SAMLObject, SAMLObject>();
        messageContext.setInboundMessageTransport(new HttpServletRequestAdapter(request));
        return messageContext;
    }
	

	/**
	 * Get session index for a LogoutRequest.
	 * 
	 * @return The value. <code>null</code>, if the logout request does not
	 *         contain any session indeces.
	 */
	public String getSessionIndex() {
		String retVal = null;
		if (request.getSessionIndexes() != null && request.getSessionIndexes().size() > 0) {
			SessionIndex sessionIndexStructure = request.getSessionIndexes().get(0);

			retVal = sessionIndexStructure.getSessionIndex();
		}
		return retVal;
	}

	/**
	 * 
	 * @param sessionIndex The sessionIndex 
	 * @return true, if the sessionIndex of the LogoutRequest match the sessionIndex
	 */
	public boolean isSessionIndexOK(String sessionIndex) {
		String sessionIndex2 = getSessionIndex();
		return sessionIndex2 != null && sessionIndex2.equals(sessionIndex);
	}
	
	public void validateRequest(String signature, String queryString, PublicKey publicKey, String destination, String issuer) throws LogoutRequestValidationException {
		validateRequest(signature, queryString, Collections.singletonList(publicKey), destination, issuer);
	}
	
	public void validateRequest(String signature, String queryString, Collection<PublicKey> keys, String destination, String issuer) throws LogoutRequestValidationException {
		List<String> errors = new ArrayList<String>();
		validateRequest(issuer, destination, keys, errors);
		
		if (signature != null) {
			boolean valid = false;
			for (PublicKey publicKey : keys) {
				if (Utils.verifySignature(signature, queryString, Constants.SAML_SAMLREQUEST, publicKey)) {
					valid = true;
				}
			}
			if (!valid) {
				errors.add("Invalid signature");
			}
		}

		if (request.getNotOnOrAfter() != null && !ClockSkewValidator.isAfterNow(request.getNotOnOrAfter())) {
			errors.add("LogoutRequest is expired. NotOnOrAfter; " + request.getNotOnOrAfter());
		}

		if (!errors.isEmpty()) {
			throw new LogoutRequestValidationException(errors);
		} 
	}

	/**
	 * Generate a new LogoutRequest.
	 * 
	 * @param session The session containing the active assertion.
	 * @param logoutServiceLocation Destination for the logout request.
	 * @param issuerEntityId Entity ID of the issuing entity.
	 */
	@SuppressWarnings("deprecation")
	public static OIOLogoutRequest buildLogoutRequest(HttpSession session, String logoutServiceLocation, String issuerEntityId, SessionHandler handler) {
		LogoutRequest logoutRequest = new LogoutRequestBuilder().buildObject();

		logoutRequest.setID(Utils.generateUUID());
		logoutRequest.setIssueInstant(new DateTime(DateTimeZone.UTC));
		logoutRequest.addNamespace(OIOSAMLConstants.SAML20_NAMESPACE);
		logoutRequest.setDestination(logoutServiceLocation);
		logoutRequest.setReason("urn:oasis:names:tc:SAML:2.0:logout:user");
		logoutRequest.setIssuer(SAMLUtil.createIssuer(issuerEntityId));

		OIOAssertion assertion = handler.getAssertion(session.getId());
		if (assertion != null) {
			NameID nameID = SAMLUtil.createNameID(assertion.getSubjectNameIDValue());
			nameID.setFormat(assertion.getAssertion().getSubject().getNameID().getFormat());
			logoutRequest.setNameID(nameID);
			SessionIndex sessionIndex = new SessionIndexBuilder().buildObject();
			logoutRequest.getSessionIndexes().add(sessionIndex);
			sessionIndex.setSessionIndex(assertion.getSessionIndex());
		}

		try {
			if (log.isDebugEnabled()) {
				log.debug("Validate the logoutRequest...");
			}
			logoutRequest.validate(true);
			if (log.isDebugEnabled()) {
				log.debug("...OK");
			}
		} catch (ValidationException e) {
			throw new WrappedException(Layer.CLIENT, e);
		}

		return new OIOLogoutRequest(logoutRequest);
	}


	/**
	 * Generate a redirect request url from the request.
	 * 
	 * The url will be signed and formatted correctly according to the HTTP Redirect SAML binding.
	 *
	 * @param signingCredential Credential to use for signing the url.
	 * @return A URL containing a &lt;LogoutRequest&gt; for the current user.
	 */
	public String getRedirectRequestURL(Credential signingCredential) {
		Encoder enc = new Encoder();

		try {
			return enc.buildRedirectURL(signingCredential, null);
		} catch (MessageEncodingException e) {
			throw new WrappedException(Layer.CLIENT, e);
		}
	}
	
    /**
	 * Set the logout reason. Defaults to urn:oasis:names:tc:SAML:2.0:logout:user.
	 */
	public void setReason(String reason) {
		request.setReason(reason);
	}

}
