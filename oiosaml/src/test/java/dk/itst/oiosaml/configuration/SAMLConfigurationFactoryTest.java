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
 * The Initial Developer of the Original Code is Trifork A/S. 
 * 2012 Danish National IT and Telecom Agency (http://www.itst.dk). 
 * All Rights Reserved.
 * 
 * Contributor(s):
 *   Aage Nielsen <ani@openminds.dk>
 *
 */
package dk.itst.oiosaml.configuration;

import static org.junit.Assert.*;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class SAMLConfigurationFactoryTest {

	
	@Before
	public void setUp() throws Exception {
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testGetConfiguration() {
		assertNotNull(SAMLConfigurationFactory.getConfiguration());
	}
}
