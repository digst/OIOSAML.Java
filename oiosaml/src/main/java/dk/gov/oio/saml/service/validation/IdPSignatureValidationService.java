package dk.gov.oio.saml.service.validation;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;

import dk.gov.oio.saml.service.IdPMetadataService;
import dk.gov.oio.saml.util.ExternalException;
import dk.gov.oio.saml.util.InternalException;

/**
 * Signatures made by the IdP, validated against the signing keys it publishes in its metadata.
 */
public class IdPSignatureValidationService {

    private IdPSignatureValidationService() {
    }

    /**
     * Every signing key the IdP publishes, as credentials.
     *
     * <p>The IdP publishes both the outgoing and the incoming key while it rotates, and either of them can be
     * the one in use at any moment, so callers have to accept a signature made with any of them rather than
     * with the first alone.</p>
     *
     * @throws InternalException if the metadata holds no usable signing certificate, since no signature from
     *         the IdP could then be validated at all
     */
    public static List<Credential> getIdPSigningCredentials() throws ExternalException, InternalException {
        List<X509Certificate> certificates = IdPMetadataService.getInstance().getIdPMetadata().getValidX509Certificates(UsageType.SIGNING);
        if (certificates.isEmpty()) {
            throw new InternalException("No valid signing certificate found in IdP metadata");
        }

        List<Credential> credentials = new ArrayList<>(certificates.size());
        for (X509Certificate certificate : certificates) {
            credentials.add(new BasicX509Credential(certificate));
        }

        return credentials;
    }

    /**
     * Validate that a signature was made with one of the signing keys the IdP publishes.
     *
     * <p>This establishes the key alone. That the signature also covers the element about to be consumed is a
     * separate property, established by SAMLSignatureProfileValidator, and callers need both.</p>
     *
     * @throws SignatureException if the signature was made with none of the published keys
     */
    public static void validateSignedByIdP(Signature signature) throws SignatureException, ExternalException, InternalException {
        SignatureException lastFailure = null;

        for (Credential credential : getIdPSigningCredentials()) {
            try {
                SignatureValidator.validate(signature, credential);
                return;
            }
            catch (SignatureException e) {
                lastFailure = e;
            }
        }

        throw new SignatureException("Signature was not made with any of the signing keys published by the IdP", lastFailure);
    }
}
