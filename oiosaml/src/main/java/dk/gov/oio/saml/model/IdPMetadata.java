package dk.gov.oio.saml.model;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import javax.net.ssl.SSLContext;

import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.TrustStrategy;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.joda.time.DateTime;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.metadata.resolver.impl.AbstractReloadingMetadataResolver;
import org.opensaml.saml.metadata.resolver.impl.FilesystemMetadataResolver;
import org.opensaml.saml.metadata.resolver.impl.HTTPMetadataResolver;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.SingleLogoutService;
import org.opensaml.security.credential.UsageType;

import dk.gov.oio.saml.config.Configuration;
import dk.gov.oio.saml.service.CRLChecker;
import dk.gov.oio.saml.service.OIOSAML3Service;
import dk.gov.oio.saml.util.ExternalException;
import dk.gov.oio.saml.util.InternalException;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;

public class IdPMetadata {
    private static final Logger log = Logger.getLogger(IdPMetadata.class);
    private List<X509Certificate> validEncryptionCertificates = new ArrayList<>();
    private List<X509Certificate> validSigningCertificates = new ArrayList<>();
    private List<X509Certificate> validUnspecifiedCertificates = new ArrayList<>();
    private String metadataFilePath;
    private AbstractReloadingMetadataResolver resolver;
    private DateTime lastCRLCheck;
    private String entityId;
    private String metadataURL;

    public IdPMetadata(String entityId, String metadataURL, String metadataFilePath) throws ExternalException, InternalException {
        this.entityId = entityId;
        this.metadataURL = metadataURL;
        this.metadataFilePath = metadataFilePath;
        getEntityDescriptor(); // Fetch metadata first time
    }

    public EntityDescriptor getEntityDescriptor() throws InternalException, ExternalException {
        // Create and initialize metadata resolver if no already initialized
        initMetadataResolver();

        // If last scheduled refresh failed, Refresh now to give up to date metadata
        if (!resolver.wasLastRefreshSuccess()) {
            if (log.isDebugEnabled()) {
                log.debug("Last Metadata was not successful, Refreshing metadata.");
            }

            try {
                resolver.refresh();
            } catch (ResolverException e) {
                throw new ExternalException("Could not get Metadata from url", e);
            }
        }

        // Extract EntityDescriptor by configured EntityID
        CriteriaSet criteriaSet = new CriteriaSet();
        criteriaSet.add(new EntityIdCriterion(entityId));

        try {
            EntityDescriptor entityDescriptor = resolver.resolveSingle(criteriaSet);
            return entityDescriptor;
        } catch (ResolverException e) {
            throw new InternalException("Configured entityID not found in metadata", e);
        }
    }

    public IDPSSODescriptor getSSODescriptor() throws ExternalException, InternalException {
        return getEntityDescriptor().getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
    }

    public X509Certificate getValidX509Certificate(UsageType usageType) throws InternalException, ExternalException {
    	doRevocationCheck();

        X509Certificate result = null;
        if (UsageType.ENCRYPTION.equals(usageType)) {
            if (validEncryptionCertificates != null && !validEncryptionCertificates.isEmpty()) {
                result = validEncryptionCertificates.get(0);
            }
        }
        else if (UsageType.SIGNING.equals(usageType)) {
            if (validSigningCertificates != null && !validSigningCertificates.isEmpty()) {
                result = validSigningCertificates.get(0);
            }
        }

        // If certificate is not found yet, try the unspecified
        if (result == null) {
            if (validUnspecifiedCertificates != null && !validUnspecifiedCertificates.isEmpty()) {
                result = validUnspecifiedCertificates.get(0);
            }
        }

        return result;
    }

    private List<X509Certificate> getAllX509CertificatesWithUsageType(UsageType usageType) throws InternalException, ExternalException {
        ArrayList<X509Certificate> certificates = new ArrayList<>();

        // Find X509Cert in Metadata filtered by type
        org.opensaml.xmlsec.signature.X509Certificate x509Certificate = null;

        IDPSSODescriptor ssoDescriptor = getSSODescriptor();
        for (KeyDescriptor keyDescriptor : ssoDescriptor.getKeyDescriptors()) {
            if (Objects.equals(usageType, keyDescriptor.getUse())) {
                x509Certificate = keyDescriptor.getKeyInfo().getX509Datas().get(0).getX509Certificates().get(0);

                if (x509Certificate != null) {
                    // Transform opensaml x509 cert --> java x509 cert
                    byte[] bytes = Base64.decode(x509Certificate.getValue());
                    ByteArrayInputStream inputStream = new ByteArrayInputStream(bytes);
                    CertificateFactory instance = null;

                    try {
                        instance = CertificateFactory.getInstance("X.509");
                    } catch (CertificateException e) {
                        throw new InternalException("Could not create factory to parse X509 Certificate", e);
                    }

                    try {
                        certificates.add((X509Certificate) instance.generateCertificate(inputStream));
                    } catch (CertificateException e) {
                        throw new ExternalException("Could not parse X509 Certificate from Metadata", e);
                    }
                }
            }
        }

        return certificates;
    }

    public SingleLogoutService getLogoutEndpoint() throws ExternalException, InternalException {
        IDPSSODescriptor ssoDescriptor = getSSODescriptor();
        for (SingleLogoutService singleLogoutService : ssoDescriptor.getSingleLogoutServices()) {
            if (SAMLConstants.SAML2_REDIRECT_BINDING_URI.equals(singleLogoutService.getBinding())) {
                return singleLogoutService;
            }
        }
        throw new ExternalException("Could not find SLO endpoint for Redirect binding in metadata");
    }

    public String getLogoutResponseEndpoint() throws InternalException, ExternalException {
        IDPSSODescriptor idpssoDescriptor = getSSODescriptor();

        for (SingleLogoutService singleLogoutService : idpssoDescriptor.getSingleLogoutServices()) {
            if (SAMLConstants.SAML2_REDIRECT_BINDING_URI.equals(singleLogoutService.getBinding())) {
                String responseLocation = singleLogoutService.getResponseLocation();
                if (responseLocation != null && !responseLocation.isEmpty()) {
                    return responseLocation;
                }
                return singleLogoutService.getLocation();
            }
        }
        throw new ExternalException("Unable to find SingleLogoutService with binding HTTPRedirect and an ResponseLocation");
    }

    public DateTime getLastCRLCheck() {
        return lastCRLCheck;
    }

	private void doRevocationCheck() throws ExternalException, InternalException {
        Configuration config = OIOSAML3Service.getConfig();
        if (config.isCRLCheckEnabled() || config.isOcspCheckEnabled()) {
            DateTime lastUpdate = resolver.getLastUpdate();

            if (lastCRLCheck == null || (lastUpdate != null && lastUpdate.isAfter(lastCRLCheck))) {
                try {
                    // Encryption
                    Set<X509Certificate> validEncryptionCertificates = CRLChecker.checkCertificates(getAllX509CertificatesWithUsageType(UsageType.ENCRYPTION), getLastCRLCheck());
                    this.validEncryptionCertificates.clear();
                    if (validEncryptionCertificates != null) {
                        this.validEncryptionCertificates.addAll(validEncryptionCertificates);
                    }

                    // Signing
                    Set<X509Certificate> validSigningCertificates = CRLChecker.checkCertificates(getAllX509CertificatesWithUsageType(UsageType.SIGNING), getLastCRLCheck());
                    this.validSigningCertificates.clear();
                    if (validSigningCertificates != null) {
                        this.validSigningCertificates.addAll(validSigningCertificates);
                    }

                    // Unspecified
                    Set<X509Certificate> validUnspecifiedCertificates = CRLChecker.checkCertificates(getAllX509CertificatesWithUsageType(UsageType.UNSPECIFIED), getLastCRLCheck());
                    Set<X509Certificate> validNullCertificates = CRLChecker.checkCertificates(getAllX509CertificatesWithUsageType(null), getLastCRLCheck());
                    this.validUnspecifiedCertificates.clear();

                    if (validUnspecifiedCertificates != null) {
                        this.validUnspecifiedCertificates.addAll(validUnspecifiedCertificates);
                    }

                    if (validNullCertificates != null) {
                        this.validUnspecifiedCertificates.addAll(validNullCertificates);
                    }

                    lastCRLCheck = DateTime.now();
                }
                catch (ExternalException | InternalException | InitializationException e) {
                    log.error("CRL check failed", e);
                    return;
                }
            }
        }
        else {
            // If revocation is disabled, all certificates from the metadata is treated as valid
            validEncryptionCertificates = getAllX509CertificatesWithUsageType(UsageType.ENCRYPTION);
            validSigningCertificates = getAllX509CertificatesWithUsageType(UsageType.SIGNING);

            List<X509Certificate> validUnspecified = getAllX509CertificatesWithUsageType(UsageType.UNSPECIFIED);
            validUnspecified.addAll(getAllX509CertificatesWithUsageType(null));
            validUnspecifiedCertificates = validUnspecified;
        }
	}

    private void initMetadataResolver() throws InternalException, ExternalException {
        // If no Resolver exists for this ServiceProvider, create it.
        if (resolver == null || !resolver.isInitialized()) {
            // Create Resolver
            try {
                Configuration config = OIOSAML3Service.getConfig();

                CloseableHttpClient httpClient;
                if (config.isSupportSelfSigned()) {
                    TrustStrategy acceptingTrustStrategy = new TrustSelfSignedStrategy();
                    SSLContext sslContext = org.apache.http.ssl.SSLContexts.custom().loadTrustMaterial(null, acceptingTrustStrategy).build();
                    SSLConnectionSocketFactory csf = new SSLConnectionSocketFactory(sslContext, NoopHostnameVerifier.INSTANCE);
                    httpClient = HttpClients.custom().setSSLSocketFactory(csf).build();
                } else {
                    httpClient = HttpClients.createDefault();
                }

                if (metadataFilePath != null) {
                    log.debug("MetadataFilePath supplied. Using file based metadata resolver");

                    File file = null;
                    URL url = getClass().getClassLoader().getResource(metadataFilePath);
                    if (url != null) {
                    	file = new File(url.toURI());
                    }
                    else {
                    	file = new File(metadataFilePath);
                    }

                    if (!file.exists()) {
                        throw new InternalException("Could not get the configured metadata file at path: " + metadataFilePath);
                    }

                    resolver = new FilesystemMetadataResolver(file);
                } else {
                    log.debug("MetadataFilePath not supplied. Using URL based metadata resolver");
                    resolver = new HTTPMetadataResolver(httpClient, metadataURL);
                }

                resolver.setId(entityId);
                resolver.setMinRefreshDelay(1000L * 60 * 60 * config.getIdpMetadataMinRefreshDelay());
                resolver.setMaxRefreshDelay(1000L * 60 * 60 * config.getIdpMetadataMaxRefreshDelay());
            } catch (ResolverException | KeyManagementException | NoSuchAlgorithmException | URISyntaxException | KeyStoreException e) {
                throw new InternalException("Could not create MetadataResolver", e);
            }

            // Create parser pool for parsing metadata
            BasicParserPool parserPool = new BasicParserPool();
            resolver.setParserPool(parserPool);
            try {
                parserPool.initialize();
            } catch (ComponentInitializationException e) {
                throw new InternalException("Could not initialize parser pool", e);
            }

            // Initialize and save resolver for future use
            try {
                resolver.initialize();
            } catch (ComponentInitializationException e) {
                throw new ExternalException("Could not initialize MetadataResolver", e);
            }
        }
    }
}
