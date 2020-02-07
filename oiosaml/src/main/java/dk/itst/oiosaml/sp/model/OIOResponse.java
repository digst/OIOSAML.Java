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

import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Collections;

import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.xml.security.credential.Credential;

import dk.itst.oiosaml.helper.DeveloperHelper;
import dk.itst.oiosaml.logging.Logger;
import dk.itst.oiosaml.logging.LoggerFactory;
import dk.itst.oiosaml.sp.model.validation.ValidationException;
import dk.itst.oiosaml.sp.service.session.SessionHandler;

/**
 * Base class for all SAML responses.
 * 
 * 
 * @author Joakim Recht <jre@trifork.com>
 *
 */
public class OIOResponse extends OIOAbstractResponse {
	private static final Logger log = LoggerFactory.getLogger(OIOResponse.class);

	private final Response response;

	private OIOAssertion assertion;

	public OIOResponse(Response response) {
		super(response);

		this.response = response;
	}

	/**
	 * Get the id of the issuing entity.
	 * 
	 * @param handler
	 *            Handler which holds sent request ids. This is used if the response has a InResponseTo.
	 * 
	 * @throws ValidationException
	 *             If the response is unsolicited and does not contain an issuer.
	 */
	public String getOriginatingIdpEntityId(SessionHandler handler) {
		if (response.getInResponseTo() == null) {
			Issuer issuer = null;
			if (!response.getAssertions().isEmpty()) {
				issuer = response.getAssertions().get(0).getIssuer();
			}
			if (issuer == null) {
				issuer = response.getIssuer();
			}

			if (issuer == null) {
				throw new ValidationException("SAML Response does not contain a issuer, this is required for unsolicited Responses");
			}
			return issuer.getValue();
		}

		return handler.removeEntityIdForRequest(response.getInResponseTo());
	}

	public void validateAssertionSignature(Certificate certificate) {
		validateAssertionSignature(Collections.singletonList(certificate));
	}
	
	public void validateAssertionSignature(Collection<? extends Certificate> certificates) {
		if (!response.getAssertions().isEmpty()) {
			boolean valid = false;

			if (certificates.size() == 0) {
				DeveloperHelper.log("It is not possible to validate the signature on the assertion, because there are no valid certificates to check the signature against. This might be because revocation checking has failed on the IdP certificates");
			}

			for (Certificate certificate : certificates) {
				OIOAssertion ass = getAssertion();
				if (ass.verifySignature(certificate.getPublicKey())) {
					valid = true;
				}
			}

			if (!valid) {
				throw new ValidationException("The assertion is not signed correctly");
			}
		}
	}

	public void validateResponse(String expectedDestination, Certificate certificate, boolean allowPassive) throws ValidationException {
		validateResponse(expectedDestination, Collections.singletonList(certificate), allowPassive);
	}

	public void validateResponse(String expectedDestination, Collection<? extends Certificate> certificates, boolean allowPassive) throws ValidationException {
		validateResponse(null, expectedDestination, allowPassive);

		if (!isPassive() && response.getAssertions().isEmpty() && response.getEncryptedAssertions().isEmpty()) {
			throw new ValidationException("Response must contain an Assertion or EncryptedAssertion.");
		}

		if (!hasSignature()) {
			return;
		}

		boolean valid = false;
		for (Certificate certificate : certificates) {
			if (verifySignature(certificate.getPublicKey())) {
				valid = true;
			}
		}

		if (!valid) {
			throw new ValidationException("The response is not signed correctly");
		}
	}

	/**
	 * Get the response assertion.
	 */
	public OIOAssertion getAssertion() {
		if (assertion != null) {
			if (log.isDebugEnabled())
				log.debug("Found encrypted assertion, returning decrypted");
			return assertion;
		}
		return OIOAssertion.fromResponse(response);
	}

	public void decryptAssertion(Credential credential, boolean allowUnencrypted) {
		if (response.getEncryptedAssertions().size() > 0) {
			OIOEncryptedAssertion enc = new OIOEncryptedAssertion(response.getEncryptedAssertions().get(0));
			this.assertion = enc.decryptAssertion(credential);
			response.getAssertions().add(assertion.getAssertion());
		}
		else {
			if (!allowUnencrypted && !response.getAssertions().isEmpty()) {
				throw new ValidationException("Assertion is not encrypted");
			}
		}
	}

	public Response getResponse() {
		return response;
	}

	public boolean isPassive() {
		if (response.getStatus() == null) {
			return false;
		}
		else if (response.getStatus().getStatusCode() == null) {
			return false;
		}
		else if (response.getStatus().getStatusCode().getStatusCode() == null) {
			return false;			
		}

		return StatusCode.NO_PASSIVE_URI.equals(response.getStatus().getStatusCode().getStatusCode().getValue());
	}
}
