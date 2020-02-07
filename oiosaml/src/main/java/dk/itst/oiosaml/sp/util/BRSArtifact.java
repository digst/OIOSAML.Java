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
package dk.itst.oiosaml.sp.util;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import org.opensaml.common.binding.BindingException;
import org.opensaml.saml2.binding.artifact.AbstractSAML2Artifact;
import org.opensaml.saml2.binding.artifact.SAML2ArtifactBuilderFactory;
import org.opensaml.saml2.binding.artifact.SAML2ArtifactType0004;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.DatatypeHelper;

import dk.itst.oiosaml.common.OIOSAMLConstants;
import dk.itst.oiosaml.error.Layer;
import dk.itst.oiosaml.error.WrappedException;

/**
 * Utility methods related to extract the content of a SAML Artifact
 * @author lsteinth
 *
 */
public class BRSArtifact {
	public static final String VERSION = "$Id: BRSArtifact.java 2829 2008-05-13 12:11:31Z jre $";
	private static SAML2ArtifactBuilderFactory artifactFactory = new SAML2ArtifactBuilderFactory();
	
    private SAML2ArtifactType0004 samlArtifact = null;
    private final String entityId;

    /**
	 * Build the class from a base64 encoded SAML artifact
	 * 
	 * @param samlArt
	 *            The base64 encoded SAML artifact received from the Login Site
	 * @param relyingParty
	 *            The expected EntityID of the Login Site who issued the SAML artifact
	 * @throws BindingException
	 *             If the SAML artifact is not valid, e.g. does not come from
	 *             the <code>relyingParty</code>
	 */
    public BRSArtifact(String samlArt, String ... relyingParty) throws BindingException {
    	samlArtifact = decodeArtifact(samlArt);
    	entityId = validate(relyingParty);
    }
    
    /**
     * Decode the SAML artifact
     * @param samlArt The base64 encoded SAML artifact
     * @return The decoded SAML artifact
     * @throws BindingException If the SAML artifact is not valid
     */
    private static SAML2ArtifactType0004 decodeArtifact(String samlArt) throws BindingException {
		byte[] artifactBytes = Base64.decode(samlArt);
		AbstractSAML2Artifact artifact = artifactFactory.buildArtifact(artifactBytes);
		if (artifact instanceof SAML2ArtifactType0004) {
			return (SAML2ArtifactType0004) artifact;
		}
		
		throw new BindingException("The artifact is not of the expected type: SAML2ArtifactType004");
    }
    
    /**
	 * Check whether the SAML artifact is valid
	 * 
	 * @param relyingParties
	 *            The expected EntityID of the Login Site who issued the SAML
	 *            artifact If the SAML artifact is not valid, e.g. does not come
	 *            from the <code>relyingParty</code>
	 */
	private String validate(String ... relyingParties) throws BindingException {
		byte[] sourceID = samlArtifact.getSourceID();
		try {
			for (String entityID : relyingParties) {
				MessageDigest md = MessageDigest.getInstance(OIOSAMLConstants.SHA_HASH_ALGORHTM);
		        byte[] expectedSourceID = md.digest(entityID.getBytes(OIOSAMLConstants.UTF_8));

		        if (Arrays.equals(expectedSourceID, sourceID)) {

		        	return entityID;
		        }
			}

			throw new BindingException("The sourceID:"+new String(sourceID)+" does not match the expected sourceId");
		} catch (NoSuchAlgorithmException e) {
			throw new WrappedException(Layer.DATAACCESS, e);
		} catch (UnsupportedEncodingException e) {
			throw new WrappedException(Layer.DATAACCESS, e);
		}
	}

	/**
	 * Extract the endpointIndex of the SAML artifact which pin points the URL
	 * of the artifact resolution service
	 * 
	 * @return The endpointIndex
	 */
    public int getEndpointIndex() {
		byte[] endpointIndex = samlArtifact.getEndpointIndex();
		//Convert the endpointIndex to an integer
		int endpointIndexValue = 0;
        for (int i = 0; i < endpointIndex.length; i++) {
            int shift = (endpointIndex.length - 1 - i) * 8;
            endpointIndexValue += (endpointIndex[i] & 0x000000FF) << shift;
        }
        return endpointIndexValue;		
    }

    /**
     * 
     * @param endPointIndex The endPointIndex to be used
     * @param entityID The entityID of the Identity Provider
     * @return An artifact for the given enitiyID
     */
    public static SAML2ArtifactType0004 buildArtifact(int endPointIndex, String entityID) {
        try {
            byte[] endpointIndex = DatatypeHelper.intToByteArray(endPointIndex);
            byte[] trimmedIndex = new byte[2];
            trimmedIndex[0] = endpointIndex[2];
            trimmedIndex[1] = endpointIndex[3];

            MessageDigest sha1Digester = MessageDigest.getInstance(OIOSAMLConstants.SHA_HASH_ALGORHTM);
            byte[] source = sha1Digester.digest(entityID.getBytes());

            SecureRandom handleGenerator = SecureRandom.getInstance("SHA1PRNG");
            byte[] assertionHandle;
            assertionHandle = new byte[20];
            handleGenerator.nextBytes(assertionHandle);

            return new BRSArtifactType0004(trimmedIndex, source, assertionHandle);
        } catch (NoSuchAlgorithmException e) {
            throw new InternalError("JVM does not support required cryptography algorithms: SHA-1/SHA1PRNG.");
        }
    }
    
    /**
     * Get the id of the entity which sent the artifact.
     */
    public String getEntityId() {
		return entityId;
	}
}
