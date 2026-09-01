package dk.gov.oio.saml.service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.opensaml.core.config.InitializationException;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.saml.saml2.encryption.EncryptedElementTypeEncryptedKeyResolver;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.encryption.support.ChainingEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.encryption.support.EncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.SimpleRetrievalMethodEncryptedKeyResolver;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.opensaml.xmlsec.signature.support.SignatureConstants;

import dk.gov.oio.saml.util.ExternalException;
import dk.gov.oio.saml.util.InternalException;

public class AssertionService {
    private static final Logger log = LoggerFactory.getLogger(AssertionService.class);

    // Key transport and block encryption algorithms allowed by [OIO-ALG-01], identical in the OIOSAML Web
    // SSO profiles 3.0.3 and 4.0.0. Anything else, RSA-1.5 in particular, is rejected before decryption.
    // The digest and mask generation entries are not encryption algorithms: they are the parameters
    // RSA-OAEP is used with, and the Decrypter checks them against the same list.
    private static final Collection<String> ALLOWED_ENCRYPTION_ALGORITHMS = Collections.unmodifiableList(Arrays.asList(
            EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP,
            EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP11,
            EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128,
            EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256,
            EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128_GCM,
            EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES192_GCM,
            EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256_GCM,
            SignatureConstants.ALGO_ID_DIGEST_SHA1,
            EncryptionConstants.ALGO_ID_DIGEST_SHA256,
            EncryptionConstants.ALGO_ID_DIGEST_SHA512,
            EncryptionConstants.ALGO_ID_MGF1_SHA1,
            EncryptionConstants.ALGO_ID_MGF1_SHA256,
            EncryptionConstants.ALGO_ID_MGF1_SHA512));

    public Assertion getAssertion(Response response) throws InternalException, ExternalException {
        if (response.getEncryptedAssertions().size() > 0) {
            EncryptedAssertion encryptedAssertion = response.getEncryptedAssertions().get(0);

            return decryptAssertion(encryptedAssertion);
        } else if (response.getAssertions().size() > 0) {
            return response.getAssertions().get(0);
        }

        throw new ExternalException("No assertion in SAML response!");
    }

    private Assertion decryptAssertion(EncryptedAssertion encryptedAssertion) throws InternalException, ExternalException {
        log.debug("Decrypting Assertion");
        try {
            KeyInfoCredentialResolver keyResolver = null;
            try {
                List<Credential> credentials = new ArrayList<>();
                credentials.add(OIOSAML3Service.getCredentialService().getPrimaryBasicX509Credential());

                BasicX509Credential secondaryBasicX509Credential = OIOSAML3Service.getCredentialService().getSecondaryBasicX509Credential();
                if (secondaryBasicX509Credential != null) {
                    credentials.add(secondaryBasicX509Credential);
                }

                keyResolver = new StaticKeyInfoCredentialResolver(credentials);
            } catch (InitializationException e) {
                throw new InternalException("CredentialService was not initialized", e);
            }

            List<EncryptedKeyResolver> encryptedKeyResolvers = new ArrayList<>();
            encryptedKeyResolvers.add(new InlineEncryptedKeyResolver());
            encryptedKeyResolvers.add(new EncryptedElementTypeEncryptedKeyResolver());
            encryptedKeyResolvers.add(new SimpleRetrievalMethodEncryptedKeyResolver());

            ChainingEncryptedKeyResolver kekResolver = new ChainingEncryptedKeyResolver(encryptedKeyResolvers);

            Decrypter decrypter = new Decrypter(null, keyResolver, kekResolver, ALLOWED_ENCRYPTION_ALGORITHMS, null);
            decrypter.setRootInNewDocument(true);

            return decrypter.decrypt(encryptedAssertion);
        } catch (DecryptionException e) {
            throw new ExternalException("Could not decrypt provided EncryptedAssertion", e);
        }
    }
}
