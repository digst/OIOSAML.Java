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

import dk.itst.oiosaml.configuration.SAMLConfiguration;
import dk.itst.oiosaml.configuration.SAMLConfigurationFactory;
import dk.itst.oiosaml.error.Layer;
import dk.itst.oiosaml.error.WrappedException;
import dk.itst.oiosaml.logging.Logger;
import dk.itst.oiosaml.logging.LoggerFactory;
import dk.itst.oiosaml.security.SecurityHelper;
import dk.itst.oiosaml.sp.service.util.Constants;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.metadata.ArtifactResolutionService;
import org.opensaml.saml2.metadata.AttributeAuthorityDescriptor;
import org.opensaml.saml2.metadata.AttributeService;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.signature.X509Data;

import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Utility class to extract relevant values of the meta data related to the Login Site.
 * 
 * @author Joakim Recht <jre@trifork.com>
 * @author Rolf Njor Jensen <rolf@trifork.com>
 * @author Aage Nielsen <ani@openminds.dk>
 * @author Carsten Larsen <cas@schultz.dk>
 * 
 */
public class IdpMetadata {
	public static final String VERSION = "$Id: IdpMetadata.java 2964 2008-06-02 11:34:06Z jre $";
	public static final String METADATA_DIRECTORY = "common.saml2.metadata.idp.directory";
	private static IdpMetadata instance;

	private static final Logger log = LoggerFactory.getLogger(IdpMetadata.class);

	private final Map<String, Metadata> metadata = new HashMap<String, Metadata>();

	public IdpMetadata(String protocol, EntityDescriptor ... entityDescriptor) {
		for (EntityDescriptor descriptor : entityDescriptor) {
			if (metadata.containsKey(descriptor.getEntityID())) {
				metadata.get(descriptor.getEntityID()).addCertificates(new Metadata(descriptor, protocol).getCertificates());
			} else {
				metadata.put(descriptor.getEntityID(), new Metadata(descriptor, protocol));
			}
		}
	}

	public static IdpMetadata getInstance() {
		if (instance == null) {
			SAMLConfiguration configuration = SAMLConfigurationFactory.getConfiguration();
			String protocol = configuration.getSystemConfiguration().getString(Constants.PROP_PROTOCOL);
			List<XMLObject> descriptors = configuration.getListOfIdpMetadata();
			instance = new IdpMetadata(protocol, descriptors.toArray(new EntityDescriptor[descriptors.size()]));
		}
		return instance ;
	}
	
	public static void setMetadata(IdpMetadata metadata) {
		instance = metadata;
	}

	public Metadata getMetadata(String entityID) {
		Metadata md = metadata.get(entityID);
		if (md == null) {
			throw new IllegalArgumentException("No metadata found for " + entityID);
		}
		return md;
	}

	/**
	 * Check if SAML Discovery Profile should be enabled.
	 * 
	 * If more than one metadata file exists, discovery should be enabled, and this method will return true.
	 */
	public boolean enableDiscovery() {
		return metadata.size() > 1;
	}

	/**
	 * Get the first registered metadata.
	 * 
	 * This method should only be used when {@link #enableDiscovery()} returns <code>true</code>, as the 
	 * metadata list is not ordered.
	 */
	public Metadata getFirstMetadata() {
		return getMetadata(getEntityIDs().iterator().next());
	}

	public Collection<String> getEntityIDs() {
		return metadata.keySet();
	}


	public Metadata findSupportedEntity(String ... entityIds) {
		for (String entityId : entityIds) {
			Metadata md = metadata.get(entityId);
			if (md != null) {
				return md;
			}
		}
		log.debug("No supported idp found in " + Arrays.toString(entityIds) + ". Supported ids: " + metadata.keySet());
		return null;
	}

	public static class Metadata {
		private EntityDescriptor entityDescriptor;
		private IDPSSODescriptor idpSSODescriptor;
		private Collection<X509Certificate> certificates = new ArrayList<X509Certificate>();
		private Map<X509Certificate, Date> validCertificates = new HashMap<X509Certificate, Date>();

		private Metadata(EntityDescriptor entityDescriptor, String protocol) {
			this.entityDescriptor = entityDescriptor;
			idpSSODescriptor = entityDescriptor.getIDPSSODescriptor(protocol);
			try {
				X509Certificate cert = SecurityHelper.buildJavaX509Cert(getCertificateNode().getValue());
				certificates.add(cert);
			} catch (CertificateException e) {
				throw new WrappedException(Layer.BUSINESS, e);
			}
		}

		public void addCertificates(Collection<X509Certificate> certs) {
			this.certificates.addAll(certs);
		}

		/**
		 * 
		 * @return The entityID of the Login Site
		 */
		public String getEntityID() {
			return entityDescriptor.getEntityID();
		}

		/**
		 * 
		 * @return The location (URL) of {@link ArtifactResolutionService}.
		 */
		public String getArtifactResolutionServiceLocation(String binding) throws IllegalArgumentException {
			for (ArtifactResolutionService artifactResolutionService : idpSSODescriptor.getArtifactResolutionServices()) {
				if (SAMLConstants.SAML2_SOAP11_BINDING_URI.equals(artifactResolutionService.getBinding())) {
					return artifactResolutionService.getLocation();
				}
			}
			throw new IllegalArgumentException("No artifact resolution service for binding " + binding);
		}

		/**
		 * Get a signon service location for a specific binding.
		 * @param binding SAML binding name,
		 * @return The url for the location.
		 * @throws IllegalArgumentException if the binding is not present in metadata.
		 */
		public String getSingleSignonServiceLocation(String binding) throws IllegalArgumentException {
			for (SingleSignOnService service : idpSSODescriptor.getSingleSignOnServices()) {
				if (service.getBinding().equals(binding)) {
					return service.getLocation();
				}
			}
			throw new IllegalArgumentException("Binding " + binding + " not found");
		}
		
		public String getAttributeQueryServiceLocation(String binding) throws IllegalArgumentException {
			AttributeAuthorityDescriptor descriptor = entityDescriptor.getAttributeAuthorityDescriptor(SAMLConstants.SAML20P_NS);
			if (descriptor == null) throw new IllegalArgumentException("Metadata does not contain a AttributeAuthorityDescriptor");
			for (AttributeService service : descriptor.getAttributeServices()) {
				if (binding.equals(service.getBinding())) {
					return service.getLocation();
				}
			}
			throw new IllegalArgumentException("Binding " + binding + " not found in AttributeServices");
		}

		public List<SingleSignOnService> getSingleSignonServices() {
			return idpSSODescriptor.getSingleSignOnServices();
		}
		/**
		 * 
		 * @return The location (URL) of {@link SingleSignOnService} at the Login Site
		 */
		public String getSingleLogoutServiceLocation() {
			String url = null;
			if (idpSSODescriptor.getSingleLogoutServices().size() > 0) {
				SingleLogoutService singleLogoutService = idpSSODescriptor.getSingleLogoutServices().get(0);
				url = singleLogoutService.getLocation();
			}
			return url;
		}

		/**
		 * 
		 * @return The response location (URL) of {@link SingleSignOnService} at the Login Site
		 */
		public String getSingleLogoutServiceResponseLocation() {
			if (idpSSODescriptor.getSingleLogoutServices().size() > 0) {
			    List<SingleLogoutService> singleLogoutServices = idpSSODescriptor.getSingleLogoutServices();

                // Prefer POST binding - due to browser redirect limitations.
			    SingleLogoutService singleLogoutService = idpSSODescriptor.getSingleLogoutServices().get(0);
			    for (SingleLogoutService sls : singleLogoutServices) {
			        if(sls.getBinding().equals(SAMLConstants.SAML2_POST_BINDING_URI)) {
			            singleLogoutService = sls;
			            break;
			        }
                }

			    String location = singleLogoutService.getResponseLocation();
				if (location == null) {
					location = singleLogoutService.getLocation();
				}
				return location;
			}
			return null;
		}


		/**
		 * 
		 * @return The certificate node from the metadata associated with the Login
		 *         Site
		 */
		private org.opensaml.xml.signature.X509Certificate getCertificateNode() {
			if (idpSSODescriptor != null && idpSSODescriptor.getKeyDescriptors().size() > 0) {
				KeyDescriptor keyDescriptor = null;
				KeyDescriptor keyDescriptorUnspecified = null;
				
				for (KeyDescriptor kd : idpSSODescriptor.getKeyDescriptors()) {
					if (kd.getUse().equals(UsageType.SIGNING)) {
						keyDescriptor = kd;
					}
					else if (kd.getUse().equals(UsageType.UNSPECIFIED)) {
						keyDescriptorUnspecified = kd;
					}
				}
				
				// fallback to any unspecified keyDescriptor
				if (keyDescriptor == null) {
					keyDescriptor = keyDescriptorUnspecified;
				}
				
				if (keyDescriptor == null) {
					throw new IllegalStateException("IdP Metadata does not contain a KeyDescriptor for signing: " + getEntityID());
				}

				if (keyDescriptor.getKeyInfo().getX509Datas().size() > 0) {
					X509Data x509Data = keyDescriptor.getKeyInfo().getX509Datas().get(0);
					if (x509Data.getX509Certificates().size() > 0) {
						  return x509Data.getX509Certificates().get(0);
					}
				}
			}
			throw new IllegalStateException("IdP Metadata does not contain a certificate: " + getEntityID());
		}
		
		Collection<X509Certificate> getAllCertificates() {
			return certificates;
		}

		/**
		 * Get a list of all certificates for this IdP.
		 * 
		 * Any expired certificates will not be included in the list.
		 */
		public Collection<X509Certificate> getCertificates() {
			Collection<X509Certificate> res = new ArrayList<X509Certificate>();
			for (X509Certificate cert: certificates) {
				if (cert.getNotAfter().after(new Date())) {
					res.add(cert);
				} else {
					log.debug("Local Metadata certificateValidated for " + getEntityID() + " expired at " + cert.getNotAfter() + ", current: " + new Date());
				}
			}
			return res;
		}

        /**
         * Get a list of all certificates for this IdP.
         *
         * Any expired or revoked certificates will not be included in the list.
         */
        public Collection<X509Certificate> getValidCertificates() {
            Collection<X509Certificate> res = new ArrayList<X509Certificate>();
            for (X509Certificate cert: validCertificates.keySet()) {
                if (cert.getNotAfter().after(new Date())) {
                    res.add(cert);
                } else {
                    log.debug("Local Metadata certificateValidated for " + getEntityID() + " expired at " + cert.getNotAfter() + ", current: " + new Date());
                }
            }
            return res;
        }

		public void setCertificateValid(X509Certificate cert, boolean valid) {
			if (valid) {
                // HashMap does not add the cert if it already existed in the Map. Instead it is replaced with the current time of validation.
                validCertificates.put(cert, new Date());
			} else {
				validCertificates.remove(cert);
			}
		}

        /**
         * Returns the time for last successful certificate validation.
         * @param certificate certificate to from to get the time for last successful certificate validation.
         * @return the time for last successful certificate validation or null if certificate does not exist.
         */
        public Date getLastTimeForCertificationValidation(X509Certificate certificate){
            return validCertificates.get(certificate);
        }
		

		/**
		 * Find a supported login endpoint.
		 * @throws IllegalArgumentException If no services match the selected bindings. 
		 */
		public Endpoint findLoginEndpoint(String[] bindings) {
			if (bindings == null) throw new IllegalArgumentException("bindings cannot be null");
			
			for (String binding : bindings) {
				for (SingleSignOnService service : idpSSODescriptor.getSingleSignOnServices()) {
					if (service.getBinding().equalsIgnoreCase(binding)) {
						return service;
					}
				}
			}
			throw new IllegalArgumentException("No SingleSignonService found for " + Arrays.toString(bindings));
		}
		
		/**
		 * Get the name format for an attribute.
		 * 
		 * @param attribute The attribute to look for.
		 * @param defaultFormat The format to return if the attribute is not present in idp metadata.
		 */
		public String getAttributeNameFormat(String attribute, String defaultFormat) {
			for (Attribute attr : idpSSODescriptor.getAttributes()) {
				if (attribute.equals(attr.getName())) {
					return attr.getNameFormat();
				}
			}
			return defaultFormat;
		}


		public Collection<PublicKey> getPublicKeys() {
			Collection<PublicKey> res = new ArrayList<PublicKey>();
			for (X509Certificate cert : getCertificates()) {
				res.add(cert.getPublicKey());
			}
			return res;
		}
	}
	
}
