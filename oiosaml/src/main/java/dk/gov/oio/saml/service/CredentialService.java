package dk.gov.oio.saml.service;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;

import dk.gov.oio.saml.util.StringUtil;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.impl.KeyStoreCredentialResolver;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.KeyInfo;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import dk.gov.oio.saml.config.Configuration;
import dk.gov.oio.saml.util.InternalException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CredentialService {
    private static final Logger log = LoggerFactory.getLogger(CredentialService.class);

    private BasicX509Credential primaryBasicX509Credential;
    private BasicX509Credential secondaryBasicX509Credential;

    public CredentialService(Configuration config) throws InitializationException {
        log.debug("Configure credential service: '{}'", config);

        if (null == config) {
            throw new InitializationException("Cannot create credential service, missing configuration");
        }

        try {
            primaryBasicX509Credential = getBasicX509Credential(config.getKeystoreLocation(), config.getKeystorePassword(), config.getKeyAlias());

            // Validate primary keystore
            if (null == primaryBasicX509Credential) {
                throw new InternalException(String.format("Unable to retrieve '%s' from keystore file '%s'", config.getKeyAlias(), config.getKeystoreLocation()));
            }

            // Validate secondary keystore if in use
            if (StringUtil.isNotEmpty(config.getSecondaryKeystoreLocation())) {
                secondaryBasicX509Credential = getBasicX509Credential(config.getSecondaryKeystoreLocation(), config.getSecondaryKeystorePassword(), config.getSecondaryKeyAlias());

                if (null == secondaryBasicX509Credential) {
                    throw new InternalException(String.format("Unable to retrieve '%s' from secondary keystore file '%s'", config.getSecondaryKeyAlias(), config.getSecondaryKeystoreLocation()));
                }
            }
        } catch (InternalException e) {
            throw new InitializationException("Malformed configuration in 'oiosaml.servlet.keystore' or keystore file", e);
        }
    }


    public BasicX509Credential getPrimaryBasicX509Credential() throws InternalException, InitializationException {
        return primaryBasicX509Credential;
    }

    public BasicX509Credential getSecondaryBasicX509Credential() throws InternalException, InitializationException {
        return secondaryBasicX509Credential;
    }

    public KeyInfo getPublicKeyInfo(BasicX509Credential credential) throws InternalException {
        X509KeyInfoGeneratorFactory x509KeyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
        x509KeyInfoGeneratorFactory.setEmitEntityCertificate(true);
        KeyInfoGenerator keyInfoGenerator = x509KeyInfoGeneratorFactory.newInstance();

        try {
            return keyInfoGenerator.generate(credential);
        }
        catch (SecurityException e) {
            throw new InternalException("Could not generate KeyInfo Object from own Credential", e);
        }
    }

    private BasicX509Credential getBasicX509Credential(String keystoreLocation, String keystorePassword, String alias) throws InternalException {
        if (keystoreLocation == null || keystorePassword == null || alias == null) {
            return null;
        }

        KeyStore ks = keyStore(keystoreLocation, keystorePassword.toCharArray());

        Map<String, String> passwords = new HashMap<>();
        try {
            passwords.put(ks.aliases().nextElement(), keystorePassword);
        }
        catch (KeyStoreException e) {
            throw new InternalException("Keystore not initialized properly", e);
        }

        KeyStoreCredentialResolver resolver = new KeyStoreCredentialResolver(ks, passwords);
        CriteriaSet criteria = new CriteriaSet();
        EntityIdCriterion entityIdCriterion = new EntityIdCriterion(alias);
        criteria.add(entityIdCriterion);

        try {
            return (BasicX509Credential) resolver.resolveSingle(criteria);
        }
        catch (ResolverException e) {
            throw new InternalException("Could not resolve own credential by configured alias: " + alias, e);
        }
    }

    private KeyStore keyStore(String location, char[] password) throws InternalException {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            InputStream in = getClass().getClassLoader().getResourceAsStream(location);
            keyStore.load(in, password);
            return keyStore;
        }
        catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException e) {
            throw new InternalException("Could not get own credential", e);
        }
    }
}
