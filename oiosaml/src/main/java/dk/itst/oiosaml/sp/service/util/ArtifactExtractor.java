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

import javax.servlet.http.HttpServletRequest;

import dk.itst.oiosaml.logging.Logger;
import dk.itst.oiosaml.logging.LoggerFactory;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.opensaml.common.binding.BindingException;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.ArtifactResolve;
import org.opensaml.saml2.core.ArtifactResponse;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.util.XMLHelper;
import org.opensaml.xml.validation.ValidationException;

import dk.itst.oiosaml.common.OIOSAMLConstants;
import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.error.Layer;
import dk.itst.oiosaml.error.WrappedException;
import dk.itst.oiosaml.logging.Audit;
import dk.itst.oiosaml.logging.Operation;
import dk.itst.oiosaml.sp.metadata.IdpMetadata;
import dk.itst.oiosaml.sp.model.OIOResponse;
import dk.itst.oiosaml.sp.util.BRSArtifact;

public class ArtifactExtractor  {
	private static final Logger log = LoggerFactory.getLogger(ArtifactExtractor.class);
	private final String spEntityID;
	private String resolveUsername;
	private String resolvePassword;
	private final IdpMetadata idpMetadata;
	private final SOAPClient client;
	private final boolean ignoreCertPath;
	
	public ArtifactExtractor(IdpMetadata idpMetadata, String spEntityID, SOAPClient client, String resolveUsername, String resolvePassword, boolean ignoreCertPath) {
		this.idpMetadata = idpMetadata;
		this.spEntityID = spEntityID;
		this.client = client;
		this.resolveUsername = resolveUsername;
		this.resolvePassword = resolvePassword;
		this.ignoreCertPath = ignoreCertPath;
	}
	

	public OIOResponse extract(HttpServletRequest request) throws IOException {
		String samlArt = request.getParameter(Constants.SAML_SAMLART);
		if (log.isDebugEnabled()) log.debug("Got SAMLart..:" + samlArt);
		
		if (samlArt == null) {
			throw new IllegalArgumentException(" Parameter 'SAMLart' is null...");
		}

		// Extract the endPoint index from the SAML artifact
		int endpointIndex = 0;
		BRSArtifact artifact;
		try {
			artifact = new BRSArtifact(samlArt, idpMetadata.getEntityIDs().toArray(new String[0]));
			endpointIndex = artifact.getEndpointIndex();
			if (log.isDebugEnabled()) log.debug("Got endpointIndex..:" + endpointIndex);
		} catch (BindingException e) {
			throw new WrappedException(Layer.BUSINESS, e);
		} catch (NullPointerException e) {
			throw new IllegalArgumentException(samlArt, e);
		}
		String artifactResolutionServiceLocation = idpMetadata.getMetadata(artifact.getEntityId()).getArtifactResolutionServiceLocation(SAMLConstants.SAML2_SOAP11_BINDING_URI);
		
		// Build the <ArtifactResolve>
		String id = Utils.generateUUID();
		ArtifactResolve artifactResolve = buildArtifactResolve(samlArt, id, artifactResolutionServiceLocation);
		
		Audit.log(Operation.ARTIFACTRESOLVE, true, artifactResolve.getID(), XMLHelper.nodeToString(SAMLUtil.marshallObject(artifactResolve)));

		Envelope env = client.wsCall(artifactResolve, artifactResolutionServiceLocation, resolveUsername, resolvePassword, ignoreCertPath);
		ArtifactResponse artifactResponse = (ArtifactResponse)env.getBody().getUnknownXMLObjects().get(0); 
		try {
			artifactResponse.validate(false);
		} catch (ValidationException e) {
			throw new WrappedException(Layer.CLIENT, e);
		}

		// Check that the <ArtifactResponse> belongs to the sent
		// <ArtifactResolve>
		if (!id.equals(artifactResponse.getInResponseTo())) {
			RuntimeException e = new RuntimeException("Received different id than I sent: Expected " + id + ". Was " + artifactResponse.getInResponseTo());
			Audit.logError(Operation.ARTIFACTRESOLVE, false, artifactResolve.getID(), e);
			throw e;
		}

		// Check whether the <ArtifactResponse> has status=SUCCESS
		String statusCode = artifactResponse.getStatus().getStatusCode().getValue();
		if (!StatusCode.SUCCESS_URI.equals(statusCode)) {
			RuntimeException e = new RuntimeException("Got ArtifactResponse:StatusCode " + statusCode + " should be " + StatusCode.SUCCESS_URI);
			Audit.logError(Operation.ARTIFACTRESOLVE, false, artifactResolve.getID(), e);
			throw e;
		}
		OIOResponse response = new OIOResponse((Response) artifactResponse.getMessage());
		Audit.log(Operation.ARTIFACTRESOLVE, false, artifactResolve.getID(), response.toXML());
		return response;
	}

	/**
	 * @param artifactValue
	 *            The SAML artifact
	 * @param id
	 *            The id of the request
	 * @param artifactResolutionLocation 
	 * @return An {@link ArtifactResolve} object relating to an artifact
	 */
	@SuppressWarnings("deprecation")
	private ArtifactResolve buildArtifactResolve(String artifactValue, String id, String artifactResolutionLocation) {

		if (log.isDebugEnabled())
			log.debug("buildArtifactResolve...");
		// Build an ArtifactResolve
		ArtifactResolve artifactResolve = SAMLUtil.buildXMLObject(ArtifactResolve.class);
		artifactResolve.addNamespace(OIOSAMLConstants.SAML20_NAMESPACE);
		artifactResolve.setIssuer(SAMLUtil.createIssuer(spEntityID));
		artifactResolve.setID(id);
		artifactResolve.setIssueInstant(new DateTime(DateTimeZone.UTC));
		artifactResolve.setArtifact(SAMLUtil.createArtifact(artifactValue));
		artifactResolve.setDestination(artifactResolutionLocation);

		// Validate the built SAML object
		try {
			artifactResolve.validate(true);
		} catch (ValidationException e) {
			throw new WrappedException(Layer.CLIENT, e);
		}
		return artifactResolve;
	}

}
