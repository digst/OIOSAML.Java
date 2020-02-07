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

import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder;
import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.opensaml.xml.validation.ValidationException;

/**
 * Base class for all SAML requests.
 * 
 * @author Joakim Recht <jre@trifork.com>
 *
 */
public abstract class OIORequest extends OIOSamlObject {

	private final RequestAbstractType request;

	public OIORequest(RequestAbstractType request) {
		super(request);
		this.request = request;
	}
	
	
	/**
	 * 
	 * @param destination The expected destination
	 * @return <code>true</code>, if the destination is match the destination in the &lt;SAMLRequest&gt; - otherwise <code>false</code>. 
	 * If there is no destination, <code>true</code> is returned.
	 */
	public boolean isDestinationOK(String destination) {
		if (request.getDestination() == null) return true;
		
		return request.getDestination() != null && request.getDestination().equals(destination);
	}
	
	/**
	 * @return true, if the issuer of the SAML Request match the expected
	 */
	public boolean isIssuerOK(String issuer) {
		return request.getIssuer() != null
				&& request.getIssuer().getValue() != null
				&& request.getIssuer().getValue().equals(
						issuer);
	}

	protected final void validateRequest(String expectedIssuer, String expectedDestination, PublicKey publicKey, List<String> errors) {
		validateRequest(expectedIssuer, expectedDestination, Collections.singletonList(publicKey), errors);
	}
	
	protected final void validateRequest(String expectedIssuer, String expectedDestination, Collection<PublicKey> keys, List<String> errors) {
		try {
			request.validate(true);
		} catch (ValidationException e) {
			errors.add(e.getMessage());
		}
		if (!isDestinationOK(expectedDestination)) {
			errors.add("Wrong destination. Expected " + expectedDestination + " but was " + request.getDestination());
		}
		if (!isIssuerOK(expectedIssuer)) {
			errors.add("Wring issuer. Expected " + expectedIssuer + " but was " + request.getIssuer());
		}
		if (hasSignature()) {
			boolean valid = false;
			for (PublicKey key : keys) {
				if (verifySignature(key)) {
					valid = true;
				}
			}
			if (!valid) {
				errors.add("Invalid signature in SAMLObject");
			}
		}
	}
	
	/**
	 * Get the request ID.
	 */
	public String getID() {
		return request.getID();
	}

	/**
	 * Get the request issuer.
	 * @return The issuer value or <code>null</code> if there is no issuer.
	 */
	public String getIssuer() {
		return request.getIssuer() != null ? request.getIssuer().getValue() : null;
	}
	
    public String getDestination() {
        return request.getDestination();
    }

    protected class Encoder extends HTTPRedirectDeflateEncoder {
		public String buildRedirectURL(Credential signingCredential, String relayState) throws MessageEncodingException {
			SAMLMessageContext<?, RequestAbstractType, ?> messageContext = new BasicSAMLMessageContext<SAMLObject, RequestAbstractType, SAMLObject>();
			// Build the parameters for the request
			messageContext.setOutboundSAMLMessage(request);
			messageContext.setRelayState(relayState);

			// Sign the parameters
			messageContext.setOutboundSAMLMessageSigningCredential(signingCredential);

            String messageStr = XMLHelper.nodeToString(marshallMessage(request));

            ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
            Deflater deflater = new Deflater(Deflater.DEFLATED, true);
            DeflaterOutputStream deflaterStream = new DeflaterOutputStream(bytesOut, deflater);
            try {
				deflaterStream.write(messageStr.getBytes("UTF-8"));
				deflaterStream.finish();
			} catch (IOException e) {
				throw new RuntimeException("Unable to deflate message", e);
			}

            String encoded = Base64.encodeBytes(bytesOut.toByteArray(), Base64.DONT_BREAK_LINES);
			return super.buildRedirectURL(messageContext, request.getDestination(), encoded);
		}
	}

}
