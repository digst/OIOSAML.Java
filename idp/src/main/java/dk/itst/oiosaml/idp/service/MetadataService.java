package dk.itst.oiosaml.idp.service;

import dk.itst.oiosaml.idp.config.ServiceProvider;
import dk.itst.oiosaml.idp.config.ServiceProviderConfig;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import org.apache.http.client.HttpClient;
import org.bouncycastle.util.encoders.Base64;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.metadata.resolver.impl.HTTPMetadataResolver;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.security.credential.UsageType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.Timer;


@Service
@Slf4j
public class MetadataService {

    @Autowired
    private HttpClient httpClient;

    @Autowired
    private ServiceProviderConfig serviceProviderConfig;

    @Value("${test.serviceProvider.entityId}")
    private String serviceProviderEntityId;

    @Value("${test.serviceProvider.metadata.URL}")
    private String serviceProviderMetadataURL;

    private HTTPMetadataResolver resourceResolver;

    public EntityDescriptor getMetadataByServiceProviderId(String entityId) {
        Optional<ServiceProvider> match = serviceProviderConfig.getProviders().stream().filter(serviceProvider -> serviceProvider.getEntityID().equals(entityId)).findFirst();
        if (match.isPresent()) {
            ServiceProvider serviceProvider = match.get();

            return getSPMetadataByURL(serviceProvider);
        }
        return null;
    }


    public EntityDescriptor getSPMetadataByURL(ServiceProvider serviceProvider) {
        try {
            // Maybe use FileBackedHTTPMetadataResolver
            HTTPMetadataResolver resolver = new HTTPMetadataResolver(new Timer(), httpClient, serviceProvider.getMetadataURL());
            resolver.setId("1");
            resolver.setMaxRefreshDelay(1000 * 60 * 24);
            resolver.setMinRefreshDelay(1000 * 60 * 2);
            resolver.setRequireValidMetadata(true);


            BasicParserPool parserPool = new BasicParserPool();
            parserPool.initialize();
            resolver.setParserPool(parserPool);

            resolver.initialize();

            CriteriaSet criteriaSet = new CriteriaSet();
            criteriaSet.add(new EntityIdCriterion(serviceProvider.getEntityID()));
            EntityDescriptor entityDescriptor = resolver.resolveSingle(criteriaSet);

            if (entityDescriptor != null) {
                return entityDescriptor;
            }
        } catch (ResolverException | ComponentInitializationException e) {
            e.printStackTrace();
        }

        return null;
    }

    public PublicKey getSPSigningKey(String entityId) throws CertificateException {
        EntityDescriptor metadata = getSPMetadata();
        SPSSODescriptor spssoDescriptor = metadata.getSPSSODescriptor(SAMLConstants.SAML20P_NS);

        Optional<KeyDescriptor> match = spssoDescriptor.getKeyDescriptors().stream()
                .filter(keyDescriptor -> keyDescriptor.getUse().equals(UsageType.SIGNING)).findFirst();

        if (!match.isPresent()) {
            log.warn("Could not find a Signing key");
            return null;
        }

        org.opensaml.xmlsec.signature.X509Certificate x509Certificate = match.get().getKeyInfo().getX509Datas().get(0).getX509Certificates().get(0);

        byte[] bytes = Base64.decode(x509Certificate.getValue());

        ByteArrayInputStream inputStream = new ByteArrayInputStream(bytes);

        CertificateFactory instance = CertificateFactory.getInstance("X.509");

        X509Certificate certificate = (X509Certificate) instance.generateCertificate(inputStream);
        return certificate.getPublicKey();
    }

    public EntityDescriptor getSPMetadata() {
        try {
            if (resourceResolver == null || !resourceResolver.isInitialized()) {
                resourceResolver = new HTTPMetadataResolver(httpClient, serviceProviderMetadataURL);
                BasicParserPool parserPool = new BasicParserPool();
                parserPool.initialize();
                resourceResolver.setParserPool(parserPool);

                resourceResolver.setId(serviceProviderEntityId);

                resourceResolver.setMinRefreshDelay(1000 * 60 * 5);
                resourceResolver.setMaxRefreshDelay(1000 * 60 * 5);

                resourceResolver.initialize();
            }

            // If last scheduled refresh failed, Refresh now to give up to date metadata
            if (!resourceResolver.wasLastRefreshSuccess()) {
                resourceResolver.refresh();
            }

            CriteriaSet criteriaSet = new CriteriaSet();
            criteriaSet.add(new EntityIdCriterion(serviceProviderEntityId));
            return resourceResolver.resolveSingle(criteriaSet);

        } catch (ResolverException | ComponentInitializationException e) {
            e.printStackTrace();
        }

        return null;
    }
}