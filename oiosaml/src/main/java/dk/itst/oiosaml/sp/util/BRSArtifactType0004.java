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

import org.opensaml.saml2.binding.artifact.SAML2ArtifactType0004;

/**
 * Super class of the Open SAML artifact implementation to fix a current
 * bug in the Open SAML class
 * @author lsteinth
 *
 */
public class BRSArtifactType0004 extends SAML2ArtifactType0004 {
	public static final String VERSION = "$Id: BRSArtifactType0004.java 2829 2008-05-13 12:11:31Z jre $";

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.opensaml.saml2.binding.artifact.SAML2ArtifactType0004#SAML2ArtifactType0004(byte[], byte[], byte[])
	 */
	public BRSArtifactType0004(byte[] endpointIndex, byte[] source, byte[] handle) {
		super(endpointIndex, source, handle);
		// OpenSAML forgets to set the TYPE_CODE, so we have to set it here
		this.setTypeCode(SAML2ArtifactType0004.TYPE_CODE);
	}

}
