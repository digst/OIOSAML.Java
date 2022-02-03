package dk.gov.oio.saml.service;

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

import dk.gov.oio.saml.util.InternalException;
import dk.gov.oio.saml.util.SamlHelper;
import net.shibboleth.utilities.java.support.security.RandomIdentifierGenerationStrategy;

public class LogoutRequestService {
    public void validateLogoutRequest() {
        return;
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
