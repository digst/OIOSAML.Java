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
 *   Aage Nielsen <ani@openminds.dk>
 *   Carsten Larsen <cas@schultz.dk>
 *
 */
package dk.itst.oiosaml.sp.metadata;

import java.security.cert.CertificateEncodingException;

import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.util.Base64;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.configuration.SAMLConfiguration;
import dk.itst.oiosaml.configuration.SAMLConfigurationFactory;
import dk.itst.oiosaml.sp.model.OIOSamlObject;
import dk.itst.oiosaml.sp.service.util.Constants;

/**
 * Utility class to extract relevant values of the meta data related to the
 * service provider.
 * 
 * @author Joakim Recht <jre@trifork.com>
 * @author Rolf Njor Jensen <rolf@trifork.com>
 * @author Aage Nielsen <ani@openminds.dk>
 * @author Carsten Larsen <cas@schultz.dk>
 *
 */
public class SPMetadata {
	public static final String VERSION = "$Id: SPMetadata.java 2950 2008-05-28 08:22:34Z jre $";
	private EntityDescriptor entityDescriptor;
	private SPSSODescriptor spSSODescriptor;
	private static SPMetadata instance;

	public SPMetadata(EntityDescriptor entityDescriptor, String protocol) {
		this.entityDescriptor = entityDescriptor;
		spSSODescriptor = entityDescriptor.getSPSSODescriptor(protocol);
	}

	public static SPMetadata getInstance() {
		if (instance == null) {
			SAMLConfiguration configuration = SAMLConfigurationFactory.getConfiguration();
			instance = new SPMetadata((EntityDescriptor) configuration.getSPMetaData(), configuration.getSystemConfiguration().getString(Constants.PROP_PROTOCOL));
		}
		return instance;
	}

	public static void setMetadata(SPMetadata metadata) {
		instance = metadata;
	}

	/**
	 * 
	 * @return The entityID of the service provider
	 */
	public String getEntityID() {
		return entityDescriptor.getEntityID();
	}

	/**
	 * Get the default assertion consumer service. If there is no default, the
	 * first is selected.
	 */
	public AssertionConsumerService getDefaultAssertionConsumerService() {
		AssertionConsumerService service = spSSODescriptor.getDefaultAssertionConsumerService();
		if (service != null)
			return service;
		if (spSSODescriptor.getAssertionConsumerServices().isEmpty())
			throw new IllegalStateException("No AssertionConsumerServices defined in SP metadata");
		return spSSODescriptor.getAssertionConsumerServices().get(0);
	}

	/**
	 * 
	 * @param index
	 * @return The location (URL) of {@link AssertionConsumerService} no.
	 *         <code>index</code> at the service provider
	 */
	public String getAssertionConsumerServiceLocation(int index) {
		if (spSSODescriptor.getAssertionConsumerServices().size() > index) {
			AssertionConsumerService consumerService = spSSODescriptor.getAssertionConsumerServices().get(index);
			return consumerService.getLocation();
		}
		return null;
	}

	/**
	 * 
	 * @return The location (URL) of {@link SingleSignOnService} at the service
	 *         provider for HTTP-Redirect
	 */
	public String getSingleLogoutServiceHTTPRedirectLocation() {
		for (SingleLogoutService singleLogoutService : spSSODescriptor.getSingleLogoutServices()) {
			if (SAMLConstants.SAML2_REDIRECT_BINDING_URI.equals(singleLogoutService.getBinding())) {
				return singleLogoutService.getLocation();
			}
		}
		return null;
	}

	/**
	 * 
	 * @return The response location (URL) of {@link SingleLogoutService} at the
	 *         service provider for HTTP-Redirect
	 */
	public String getSingleLogoutServiceHTTPRedirectResponseLocation() {
		for (SingleLogoutService singleLogoutService : spSSODescriptor.getSingleLogoutServices()) {
			if (SAMLConstants.SAML2_REDIRECT_BINDING_URI.equals(singleLogoutService.getBinding())) {
				return singleLogoutService.getResponseLocation();
			}
		}
		return null;
	}

	/**
	 * 
	 * @return The location (URL) of {@link SingleLogoutService} at the service
	 *         provider for SOAP
	 */
	public String getSingleLogoutServiceSOAPLocation() {
		for (SingleLogoutService singleLogoutService : spSSODescriptor.getSingleLogoutServices()) {
			if (SAMLConstants.SAML2_SOAP11_BINDING_URI.equals(singleLogoutService.getBinding())) {
				return singleLogoutService.getLocation();
			}
		}
		return null;
	}

	/**
	 * 
	 * @return The location (URL) of {@link SingleLogoutService} at the service
	 *         provider for POST
	 */
	public String getSingleLogoutServiceHTTPPostLocation() {
		for (SingleLogoutService singleLogoutService : spSSODescriptor.getSingleLogoutServices()) {
			if (SAMLConstants.SAML2_POST_BINDING_URI.equals(singleLogoutService.getBinding())) {
				return singleLogoutService.getLocation();
			}
		}
		return null;
	}

	/**
	 * 
	 * @return The response location (URL) of {@link SingleLogoutService} at the
	 *         service provider for POST
	 */
	public String getSingleLogoutServiceHTTPPostResponseLocation() {
		for (SingleLogoutService singleLogoutService : spSSODescriptor.getSingleLogoutServices()) {
			if (SAMLConstants.SAML2_POST_BINDING_URI.equals(singleLogoutService.getBinding())) {
				return singleLogoutService.getResponseLocation();
			}
		}
		return null;
	}

	/**
	 * Get a string representation of the signed metadata.
	 * 
	 * This method replaces the KeyInfo elements in the SPMetadata.xml file with
	 * the actual certificate passed in the credentials parameter.
	 * 
	 * @param signingCredential
	 *            Credential to use for signing. If <code>null</code>, the
	 *            metadata is not signed.
	 * @return The signed metadata as a string.
	 */
	public String getMetadata(Credential signingCredential, boolean sign) {
		X509Credential c = (X509Credential) signingCredential;
		EntityDescriptor e = SAMLUtil.clone(entityDescriptor);
		for (RoleDescriptor rd : e.getRoleDescriptors()) {
			for (KeyDescriptor k : rd.getKeyDescriptors()) {
				for (X509Data data : k.getKeyInfo().getX509Datas()) {
					for (X509Certificate cert : data.getX509Certificates()) {
						try {
							cert.setValue(Base64.encodeBytes(c.getEntityCertificate().getEncoded()));
						} catch (CertificateEncodingException e1) {
							throw new RuntimeException(e1);
						}
					}
				}
			}
		}
		OIOSamlObject obj = new OIOSamlObject(e);
		if (sign) {
			obj.sign(signingCredential);
		}
		return obj.toXML();
	}
}
