package dk.gov.oio.saml.service;


import javax.servlet.http.HttpServletRequest;

import org.joda.time.DateTime;
import org.opensaml.core.config.InitializationException;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.SessionIndex;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import dk.gov.oio.saml.service.validation.IdPSignatureValidationService;
import dk.gov.oio.saml.util.ExternalException;
import dk.gov.oio.saml.util.InternalException;
import dk.gov.oio.saml.util.SamlHelper;
import net.shibboleth.utilities.java.support.security.RandomIdentifierGenerationStrategy;

public class LogoutRequestService {
    private static final Logger log = LoggerFactory.getLogger(LogoutRequestService.class);

    /**
     * Verify that an incoming LogoutRequest was issued by the configured IdP and signed with its signing key.
     *
     * <p>Accepts a signature on the message itself (POST and SOAP) or on the query string (HTTP-Redirect
     * binding), and rejects a request carrying neither. Must be called before any session is terminated.</p>
     */
    public static void validateLogoutRequest(HttpServletRequest httpServletRequest, MessageContext<SAMLObject> messageContext, LogoutRequest logoutRequest) throws ExternalException, InternalException {
        validateIssuer(logoutRequest);
        IdPSignatureValidationService.validateMessageSignedByIdP(httpServletRequest, messageContext, logoutRequest, "LogoutRequest");
    }

    private static void validateIssuer(LogoutRequest logoutRequest) throws ExternalException {
        Issuer issuer = logoutRequest.getIssuer();
        String idpEntityID = OIOSAML3Service.getConfig().getIdpEntityID();

        if (issuer == null || !idpEntityID.equals(issuer.getValue())) {
            log.warn("LogoutRequest issuer '{}' does not match the configured IdP '{}'", (issuer != null) ? issuer.getValue() : null, idpEntityID);
            throw new ExternalException("LogoutRequest was not issued by the configured IdP");
        }
    }

    public static MessageContext<SAMLObject> createMessageWithLogoutRequest(String nameID, String nameIDFormat, String destination, String index) throws InitializationException, InternalException {
        // Create message context
        MessageContext<SAMLObject> messageContext = new MessageContext<>();

        // Create AuthnRequest
        LogoutRequest outgoingLogoutRequest = createLogoutRequest(nameID, nameIDFormat, destination, index);
        messageContext.setMessage(outgoingLogoutRequest);

        // Destination
        SAMLPeerEntityContext peerEntityContext = messageContext.getSubcontext(SAMLPeerEntityContext.class, true);
        SAMLEndpointContext endpointContext = peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);

        SingleSignOnService endpoint = SamlHelper.build(SingleSignOnService.class);
        endpointContext.setEndpoint(endpoint);

        endpoint.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
        endpoint.setLocation(destination);

        // Signing info
        SignatureSigningParameters signatureSigningParameters = new SignatureSigningParameters();
        signatureSigningParameters.setSigningCredential(OIOSAML3Service.getCredentialService().getPrimaryBasicX509Credential());
        signatureSigningParameters.setSignatureAlgorithm(OIOSAML3Service.getConfig().getSignatureAlgorithm());
        messageContext.getSubcontext(SecurityParametersContext.class, true).setSignatureSigningParameters(signatureSigningParameters);

        return messageContext;
    }

    private static LogoutRequest createLogoutRequest(String nameID, String nameIDFormat, String destination, String index) throws InitializationException {
        LogoutRequest outgoingLR = SamlHelper.build(LogoutRequest.class);

        // Set ID
        RandomIdentifierGenerationStrategy secureRandomIdGenerator = new RandomIdentifierGenerationStrategy();
        String id = secureRandomIdGenerator.generateIdentifier();
        outgoingLR.setID(id);

        outgoingLR.setDestination(destination);
        outgoingLR.setIssueInstant(new DateTime());

        // Create Issuer
        Issuer issuer = SamlHelper.build(Issuer.class);
        outgoingLR.setIssuer(issuer);

        issuer.setValue(OIOSAML3Service.getConfig().getSpEntityID());

        // NameID
        NameID nameIDObj = SamlHelper.build(NameID.class);
        outgoingLR.setNameID(nameIDObj);

        nameIDObj.setFormat(nameIDFormat);
        nameIDObj.setValue(nameID);
        
        // SessionIndex
        if (index != null) {
            SessionIndex sessionIndex = SamlHelper.build(SessionIndex.class);
            sessionIndex.setSessionIndex(index);
            outgoingLR.getSessionIndexes().add(sessionIndex);
        }

        return outgoingLR;
    }
}
