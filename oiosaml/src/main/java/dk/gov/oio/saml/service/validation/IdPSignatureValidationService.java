package dk.gov.oio.saml.service.validation;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.messaging.context.SAMLProtocolContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.binding.security.impl.SAML2HTTPRedirectDeflateSignatureSecurityHandler;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.credential.impl.StaticCredentialResolver;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.SignatureValidationParameters;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

import dk.gov.oio.saml.service.IdPMetadataService;
import dk.gov.oio.saml.service.OIOSAML3Service;
import dk.gov.oio.saml.util.ExternalException;
import dk.gov.oio.saml.util.InternalException;
import dk.gov.oio.saml.util.StringUtil;

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

    /**
     * Validate that a protocol message received from the IdP is signed by it.
     *
     * <p>Accepts a signature on the message itself (POST and SOAP) or on the query string (HTTP-Redirect
     * binding), and rejects a message carrying neither.</p>
     *
     * @param messageName name of the message type, used in error messages
     */
    public static void validateMessageSignedByIdP(HttpServletRequest httpServletRequest, MessageContext<SAMLObject> messageContext, SignableSAMLObject message, String messageName) throws ExternalException, InternalException {
        if (message.isSigned()) {
            validateXmlSignature(message, messageName);
        }
        else if (StringUtil.isNotEmpty(httpServletRequest.getParameter("Signature"))) {
            validateQueryStringSignature(httpServletRequest, messageContext, messageName);
        }
        else {
            throw new ExternalException(messageName + " was not signed");
        }
    }

    private static void validateXmlSignature(SignableSAMLObject message, String messageName) throws ExternalException, InternalException {
        Signature signature = message.getSignature();
        try {
            // Establishes that the signature is bound to this message, see SAMLSignatureProfileValidator
            new SAMLSignatureProfileValidator().validate(signature);

            validateSignedByIdP(signature);
        }
        catch (SignatureException e) {
            throw new ExternalException(messageName + " signature could not be validated", e);
        }
    }

    @SuppressWarnings("unchecked")
    private static void validateQueryStringSignature(HttpServletRequest httpServletRequest, MessageContext<SAMLObject> messageContext, String messageName) throws ExternalException, InternalException {
        SAMLPeerEntityContext peerEntityContext = messageContext.getSubcontext(SAMLPeerEntityContext.class, true);
        peerEntityContext.setEntityId(OIOSAML3Service.getConfig().getIdpEntityID());
        peerEntityContext.setRole(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);

        messageContext.getSubcontext(SAMLProtocolContext.class, true).setProtocol(SAMLConstants.SAML20P_NS);

        List<Credential> idPSigningCredentials = getIdPSigningCredentials();
        SignatureValidationParameters validationParameters = new SignatureValidationParameters();
        validationParameters.setSignatureTrustEngine(new ExplicitKeySignatureTrustEngine(
                new StaticCredentialResolver(idPSigningCredentials),
                new StaticKeyInfoCredentialResolver(idPSigningCredentials)));
        messageContext.getSubcontext(SecurityParametersContext.class, true).setSignatureValidationParameters(validationParameters);

        SAML2HTTPRedirectDeflateSignatureSecurityHandler signatureHandler = new SAML2HTTPRedirectDeflateSignatureSecurityHandler();
        try {
            signatureHandler.setHttpServletRequest(httpServletRequest);
            signatureHandler.initialize();
            signatureHandler.invoke(messageContext);
        }
        catch (ComponentInitializationException e) {
            throw new InternalException("Could not initialize SAML2HTTPRedirectDeflateSignatureSecurityHandler", e);
        }
        catch (MessageHandlerException e) {
            throw new ExternalException(messageName + " signature could not be validated", e);
        }
        finally {
            if (signatureHandler.isInitialized() && !signatureHandler.isDestroyed()) {
                signatureHandler.destroy();
            }
        }

        // The handler leaves the peer unauthenticated if it did not handle the message, for instance when the
        // binding does not match, so a completed invoke is not on its own proof that the signature was checked
        if (!peerEntityContext.isAuthenticated()) {
            throw new ExternalException(messageName + " signature was not verified");
        }
    }
}
