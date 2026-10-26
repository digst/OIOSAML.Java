package dk.itst.oiosaml.idp.service;

import lombok.extern.log4j.Log4j2;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.impl.KeyStoreCredentialResolver;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.ResourceUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.util.HashMap;
import java.util.Map;

@Service
@Log4j2
public class CredentialService {
    @Value("${keystore.location}")
    private String keystoreLocation;

    @Value("${keystore.password}")
    private String keystorePassword;

    private BasicX509Credential basicX509Credential;

    public BasicX509Credential getX509Credential() {

        if (basicX509Credential != null) {
            return basicX509Credential;
        }

        try {
            if (keystoreLocation != null && keystoreLocation.length() > 0) {

                KeyStore ks = keyStore(keystoreLocation, keystorePassword.toCharArray());
                Map<String, String> passwords = new HashMap<>();
                passwords.put(ks.aliases().nextElement(), keystorePassword);
                KeyStoreCredentialResolver resolver = new KeyStoreCredentialResolver(ks, passwords);

                CriteriaSet criteria = new CriteriaSet();
                EntityIdCriterion entityIdCriterion = new EntityIdCriterion("1");
                criteria.add(entityIdCriterion);

                basicX509Credential = (BasicX509Credential) resolver.resolveSingle(criteria);
                return basicX509Credential;
            }
        } catch (Exception e) {
            log.error("Errow when parsing x.509 Credentials", e);
        }
        return null;
    }

    private KeyStore keyStore(String file, char[] password) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        File key = ResourceUtils.getFile(file);

        try (InputStream in = new FileInputStream(key)) {
            keyStore.load(in, password);
        }

        return keyStore;
    }

    public KeyInfo getPublicKeyInfo() {
        X509KeyInfoGeneratorFactory x509KeyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
        x509KeyInfoGeneratorFactory.setEmitEntityCertificate(true);
        KeyInfoGenerator keyInfoGenerator = x509KeyInfoGeneratorFactory.newInstance();

        try {
            return keyInfoGenerator.generate(getX509Credential());
        } catch (SecurityException e) {
            log.error("Unable to create KeyInfo with Public key info", e);
        }
        return null;
    }
}
