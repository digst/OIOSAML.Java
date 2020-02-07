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
 * created by Trifork A/S are Copyright (C) 2013 Danish National IT 
 * and Telecom Agency (http://www.itst.dk). All Rights Reserved.
 * 
 * Contributor(s):
 *   Aage Nielsen <ani@openminds.dk>
 *   Carsten Larsen <cas@schultz.dk>
 *
 */
package dk.itst.oiosaml.configuration;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Map;

import org.apache.commons.configuration.Configuration;
import org.opensaml.xml.XMLObject;

import dk.itst.oiosaml.error.WrappedException;
import dk.itst.oiosaml.sp.service.session.SameSiteSessionSynchronizer;

/**
 * Interface defining a configuration.
 * 
 * @author Aage Nielsen <ani@openminds.dk>
 * @author Carsten Larsen <cas@schultz.dk>
 * 
 */
public interface SAMLConfiguration {

	//String home = null;

	boolean isConfigured();

	Configuration getSystemConfiguration();

	KeyStore getKeystore() throws WrappedException, NoSuchAlgorithmException, CertificateException, IllegalStateException, IOException, KeyStoreException;

	List<XMLObject> getListOfIdpMetadata();

	XMLObject getSPMetaData();

	Configuration getCommonConfiguration() throws IOException;

	void setConfiguration(Configuration configuration);

	void setInitConfiguration(Map<String, String> params);
	
	SameSiteSessionSynchronizer getSameSiteSessionSynchronizer();
}
