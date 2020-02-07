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

import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusResponseType;

import dk.itst.oiosaml.helper.DeveloperHelper;
import dk.itst.oiosaml.sp.model.validation.ValidationException;

public class OIOAbstractResponse extends OIOSamlObject {

	private final StatusResponseType response;

	public OIOAbstractResponse(StatusResponseType response) {
		super(response);
		this.response = response;
	}

	/**
	 * @return true, if the issuer of the SAML Response match the expected
	 */
	public boolean isIssuerOK(String issuer) {
		return response.getIssuer() != null
				&& response.getIssuer().getValue() != null
				&& response.getIssuer().getValue().equals(issuer);
	}

	/**
	 * @param destination
	 *            The expected destination
	 * @return <code>true</code>, if the destination is match the destination in the
	 *         &lt;SAMLResponse&gt; - otherwise <code>false</code>. If the response does not have a destination, <code>true</code> is returned.
	 */
	public boolean isDestinationOK(String destination) {
		if (response.getDestination() == null) return true;
		
		return response.getDestination() != null && response.getDestination().equals(destination);
	}

	protected void validateResponse(String requestId, String expectedDestination, boolean allowPassive) {
		String statusCode = response.getStatus().getStatusCode().getValue();
		if (!StatusCode.SUCCESS_URI.equals(statusCode)) {
			
			StatusCode is = response.getStatus().getStatusCode().getStatusCode();
			if (is == null || !(StatusCode.NO_PASSIVE_URI.equals(is.getValue()) && allowPassive)) {
				DeveloperHelper.log("The Identity Provider responded with a non-success message. The reason for this might be because the user who tried to login is not allowed to do so (something went wrong the users username/password, certificate, access rights, etc), or because something is wrong with the metadata configuration on the Identity Provider side.");

				String msg = response.getStatus().getStatusMessage() == null ? "" : response.getStatus().getStatusMessage().getMessage();
				throw new ValidationException("Got StatusCode " + statusCode + " should be " + StatusCode.SUCCESS_URI + ". Message: " + msg);
			}
		}
		if (!isDestinationOK(expectedDestination)) {
			throw new ValidationException("Wrong destination. Expected " + expectedDestination + ", was " + response.getDestination());
		}
		
		if (requestId != null && !requestId.equals(response.getInResponseTo())) {
			throw new ValidationException("Wrong InResponseTo. Expected " + requestId + ", was " + response.getInResponseTo());
		}

	}

	public String getInResponseTo() {
		return response.getInResponseTo();
	}
	
	public String getID() {
		return response.getID();
	}

		
}
