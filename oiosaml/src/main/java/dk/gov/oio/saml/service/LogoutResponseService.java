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
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.context.SecurityParametersContext;

import dk.gov.oio.saml.util.InternalException;
import dk.gov.oio.saml.util.SamlHelper;
import net.shibboleth.utilities.java.support.security.RandomIdentifierGenerationStrategy;

public class LogoutResponseService {

	public void validateLogoutResponse() {
		return;
	}

	public static MessageContext<SAMLObject> createMessageWithLogoutResponse(LogoutRequest logoutRequest, String destination) throws InitializationException, InternalException {
		// Create message context
		MessageContext<SAMLObject> messageContext = new MessageContext<>();

		// Create AuthnRequest
		LogoutResponse logoutResponse = createLogoutResponse(destination, logoutRequest);
		messageContext.setMessage(logoutResponse);

		// Destination
		SAMLPeerEntityContext peerEntityContext = messageContext.getSubcontext(SAMLPeerEntityContext.class, true);
		SAMLEndpointContext endpointContext = peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);

		SingleSignOnService endpoint = SamlHelper.build(SingleSignOnService.class);
		endpoint.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
		endpoint.setLocation(destination);

		endpointContext.setEndpoint(endpoint);

		// Signing info
		SignatureSigningParameters signatureSigningParameters = new SignatureSigningParameters();
		signatureSigningParameters.setSigningCredential(CredentialService.getInstance().getPrimaryBasicX509Credential());
		signatureSigningParameters.setSignatureAlgorithm(OIOSAML3Service.getConfig().getSignatureAlgorithm());
		messageContext.getSubcontext(SecurityParametersContext.class, true).setSignatureSigningParameters(signatureSigningParameters);

		return messageContext;
	}

	private static LogoutResponse createLogoutResponse(String destination, LogoutRequest logoutRequest) throws InitializationException {
		LogoutResponse logoutResponse = SamlHelper.build(LogoutResponse.class);

		RandomIdentifierGenerationStrategy randomIdentifierGenerator = new RandomIdentifierGenerationStrategy();
		String id = randomIdentifierGenerator.generateIdentifier();

		logoutResponse.setID(id);
		logoutResponse.setDestination(destination);
		logoutResponse.setIssueInstant(new DateTime());
		logoutResponse.setInResponseTo(logoutRequest.getID());

		// Create Issuer
		Issuer issuer = SamlHelper.build(Issuer.class);
		logoutResponse.setIssuer(issuer);
		issuer.setValue(OIOSAML3Service.getConfig().getSpEntityID());

		Status status = SamlHelper.build(Status.class);
		logoutResponse.setStatus(status);

		StatusCode statusCode = SamlHelper.build(StatusCode.class);
		status.setStatusCode(statusCode);
		statusCode.setValue("urn:oasis:names:tc:SAML:2.0:status:Success");

		return logoutResponse;
	}
}
