package dk.gov.oio.saml.model;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;


import dk.gov.oio.saml.util.ResourceUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.bouncycastle.util.encoders.Base64;
import org.joda.time.DateTime;
import org.joda.time.Duration;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.metadata.resolver.impl.AbstractReloadingMetadataResolver;
import org.opensaml.saml.metadata.resolver.impl.FilesystemMetadataResolver;
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
    private static final Logger log = LoggerFactory.getLogger(IdPMetadata.class);
    // Revocation is checked again after this long, so a certificate revoked while the SP runs is dropped
    private static final Duration RECHECK_INTERVAL = Duration.standardHours(1);
    // Retry soon when a check validated nothing, so a short outage of OCSP/CRL does not block login for an hour
    private static final Duration RETRY_INTERVAL = Duration.standardMinutes(1);

    private volatile ValidCertificates validCertificates;
    private String metadataFilePath;
    private AbstractReloadingMetadataResolver resolver;
    private volatile DateTime lastCRLCheck;
    private String entityId;

    public IdPMetadata(String entityId, String metadataFilePath) throws ExternalException, InternalException {
        this.entityId = entityId;
        this.metadataFilePath = metadataFilePath;
        getEntityDescriptor(); // Fetch metadata first time
    }

    public EntityDescriptor getEntityDescriptor() throws InternalException, ExternalException {
        // Create and initialize metadata resolver if no already initialized
        initMetadataResolver();

        // If last scheduled refresh failed, Refresh now to give up to date metadata
        if (!resolver.wasLastRefreshSuccess()) {
            log.debug("Last Metadata was not successful, Refreshing metadata.");

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

    /**
     * All certificates the IdP publishes for the given usage that passed revocation checking.
     *
     * <p>An IdP publishes both the outgoing and the incoming certificate while it rotates a key, and either
     * of them can be the one in use at any moment, so callers have to accept all of them rather than picking
     * one.</p>
     */
    public List<X509Certificate> getValidX509Certificates(UsageType usageType) throws InternalException, ExternalException {
        doRevocationCheck();
        ValidCertificates valid = validCertificates;

        List<X509Certificate> result = new ArrayList<>();
        if (UsageType.ENCRYPTION.equals(usageType)) {
            result.addAll(valid.encryption);
        }
        else if (UsageType.SIGNING.equals(usageType)) {
            result.addAll(valid.signing);
        }

        // Certificates published without a usage serve both purposes
        result.addAll(valid.unspecified);

        // A certificate that expires while the SP runs must stop being trusted at once, not at the next check
        result.removeIf(certificate -> !CRLChecker.isWithinValidityPeriod(certificate));

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
        if (!isRevocationCheckDue()) {
            return;
        }

        synchronized (this) {
            if (!isRevocationCheckDue()) {
                return;
            }

            DateTime now = DateTime.now();
            Configuration config = OIOSAML3Service.getConfig();
            ValidCertificates checked;
            try {
                if (config.isCRLCheckEnabled() || config.isOcspCheckEnabled()) {
                    List<X509Certificate> unspecified = new ArrayList<>(CRLChecker.checkCertificates(getAllX509CertificatesWithUsageType(UsageType.UNSPECIFIED)));
                    unspecified.addAll(CRLChecker.checkCertificates(getAllX509CertificatesWithUsageType(null)));
                    checked = new ValidCertificates(
                            new ArrayList<>(CRLChecker.checkCertificates(getAllX509CertificatesWithUsageType(UsageType.ENCRYPTION))),
                            new ArrayList<>(CRLChecker.checkCertificates(getAllX509CertificatesWithUsageType(UsageType.SIGNING))),
                            unspecified,
                            now.plus(RECHECK_INTERVAL));
                }
                else {
                    // Without revocation checking, every certificate in the metadata within its validity period is valid
                    log.warn("Revocation checking of IdP certificates is disabled");
                    List<X509Certificate> unspecified = getAllX509CertificatesWithUsageType(UsageType.UNSPECIFIED);
                    unspecified.addAll(getAllX509CertificatesWithUsageType(null));
                    checked = new ValidCertificates(getAllX509CertificatesWithUsageType(UsageType.ENCRYPTION),
                            getAllX509CertificatesWithUsageType(UsageType.SIGNING), unspecified, now.plus(RECHECK_INTERVAL));
                }
            }
            catch (ExternalException | InternalException | InitializationException e) {
                log.warn("Revocation check of IdP certificates failed, retrying in {}", RETRY_INTERVAL, e);
                ValidCertificates previous = validCertificates;
                validCertificates = (previous != null) ? previous.retryAt(now.plus(RETRY_INTERVAL)) : ValidCertificates.none(now.plus(RETRY_INTERVAL));
                return;
            }

            if (checked.signing.isEmpty() && checked.unspecified.isEmpty()) {
                log.warn("No IdP signing certificate passed revocation checking, retrying in {}", RETRY_INTERVAL);
                checked = checked.retryAt(now.plus(RETRY_INTERVAL));
            }

            validCertificates = checked;
            lastCRLCheck = now;
        }
    }

    private boolean isRevocationCheckDue() {
        ValidCertificates valid = validCertificates;
        if (valid == null || !valid.nextCheck.isAfterNow()) {
            return true;
        }

        // A replaced metadata file is checked at once
        DateTime lastUpdate = resolver.getLastUpdate();
        return lastUpdate != null && lastCRLCheck != null && lastUpdate.isAfter(lastCRLCheck);
    }

    /**
     * The certificates that passed the last revocation check, replaced as a whole so readers never see a
     * partly updated set.
     */
    private static final class ValidCertificates {
        private final List<X509Certificate> encryption;
        private final List<X509Certificate> signing;
        private final List<X509Certificate> unspecified;
        private final DateTime nextCheck;

        private ValidCertificates(List<X509Certificate> encryption, List<X509Certificate> signing, List<X509Certificate> unspecified, DateTime nextCheck) {
            this.encryption = Collections.unmodifiableList(new ArrayList<>(encryption));
            this.signing = Collections.unmodifiableList(new ArrayList<>(signing));
            this.unspecified = Collections.unmodifiableList(new ArrayList<>(unspecified));
            this.nextCheck = nextCheck;
        }

        private ValidCertificates retryAt(DateTime retry) {
            return new ValidCertificates(encryption, signing, unspecified, retry);
        }

        private static ValidCertificates none(DateTime retry) {
            return new ValidCertificates(Collections.emptyList(), Collections.emptyList(), Collections.emptyList(), retry);
        }
    }

    private void initMetadataResolver() throws InternalException, ExternalException {
        // If no Resolver exists for this ServiceProvider, create it.
        if (resolver == null || !resolver.isInitialized()) {
            // Create Resolver
            try {
                Configuration config = OIOSAML3Service.getConfig();

                // Metadata is deployed as a file. The IdP does not sign its metadata, so trust in it comes
                // from the deployment of that file, not from the transport it was fetched over
                log.debug("Reading IdP metadata from {}", metadataFilePath);
                resolver = new FilesystemMetadataResolver(ResourceUtil.getResourceAsFile(metadataFilePath));

                resolver.setId(entityId);

                // The file is re-read while the SP runs, so replacing it is enough to publish new keys
                resolver.setMinRefreshDelay(1000L * 60 * 60 * config.getIdpMetadataMinRefreshDelay());
                resolver.setMaxRefreshDelay(1000L * 60 * 60 * config.getIdpMetadataMaxRefreshDelay());

                // Metadata that has passed its validUntil is not used
                resolver.setRequireValidMetadata(true);
            } catch (ResolverException e) {
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
