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
package dk.itst.oiosaml.sp.metadata;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.Test;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.xml.security.x509.BasicX509Credential;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.sp.AbstractTests;
import dk.itst.oiosaml.sp.model.OIOSamlObject;
import dk.itst.oiosaml.sp.service.TestHelper;

public class SPMetadataTest extends AbstractTests{

	@Test
	public void testGetMetadata() throws Exception {
		SPMetadata metadata = TestHelper.buildSPMetadata();
		
		BasicX509Credential credential = TestHelper.getCredential();
		String xml = metadata.getMetadata(credential, true);
		assertNotNull(xml);
		
		EntityDescriptor desc = (EntityDescriptor) SAMLUtil.unmarshallElementFromString(xml);
		assertNotNull(desc);
		
		assertEquals(metadata.getEntityID(), desc.getEntityID());
		assertNotNull(desc.getSignature());
		
		new OIOSamlObject(desc).verifySignature(credential.getPublicKey());
	}
}
