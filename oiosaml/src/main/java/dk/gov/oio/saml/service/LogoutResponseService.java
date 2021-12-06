package dk.gov.oio.saml.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.joda.time.DateTime;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.io.MarshallingException;
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
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.algorithm.descriptors.SignatureRSASHA256;
import org.opensaml.xmlsec.context.SecurityParametersContext;

import dk.gov.oio.saml.util.InternalException;
import dk.gov.oio.saml.util.SamlHelper;
import net.shibboleth.utilities.java.support.security.RandomIdentifierGenerationStrategy;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.Signer;

import javax.xml.crypto.dsig.CanonicalizationMethod;

public class LogoutResponseService {
	private static final Logger log = LoggerFactory.getLogger(LogoutResponseService.class);

	public void validateLogoutResponse() {
		return;
	}

	public static MessageContext<SAMLObject> createMessageWithLogoutResponse(LogoutRequest logoutRequest, String destination) throws InitializationException, InternalException {
		log.debug("Create and sign logout response message for  request id '{}'", logoutRequest.getID());

		// Create message context
		MessageContext<SAMLObject> messageContext = new MessageContext<>();

		// Create AuthnRequest
		LogoutResponse logoutResponse = signResponse(createLogoutResponse(destination, logoutRequest));
		messageContext.setMessage(logoutResponse);

		// Destination
		SAMLPeerEntityContext peerEntityContext = messageContext.getSubcontext(SAMLPeerEntityContext.class, true);
		SAMLEndpointContext endpointContext = peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);

		SingleSignOnService endpoint = SamlHelper.build(SingleSignOnService.class);
		endpoint.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
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
		log.debug("Create logout response message for  request id '{}'", logoutRequest.getID());

		LogoutResponse logoutResponse = SamlHelper.build(LogoutResponse.class);

		RandomIdentifierGenerationStrategy randomIdentifierGenerator = new RandomIdentifierGenerationStrategy();
		String id = randomIdentifierGenerator.generateIdentifier();

 		log.debug("Created logout response id '" + id + "' for  request id '" + logoutRequest.getID() + "'");

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

	private static LogoutResponse signResponse(LogoutResponse logoutResponse) {
		log.debug("Signing logout response message with id '{}'", logoutResponse.getID());
		try {
			Signature signature = SamlHelper.build(Signature.class);

			BasicX509Credential x509Credential = CredentialService.getInstance().getPrimaryBasicX509Credential();
			SignatureRSASHA256 signatureRSASHA256 = new SignatureRSASHA256();

			signature.setSigningCredential(x509Credential);
			signature.setCanonicalizationAlgorithm(CanonicalizationMethod.EXCLUSIVE);
			signature.setSignatureAlgorithm(signatureRSASHA256.getURI());
			signature.setKeyInfo(CredentialService.getInstance().getPublicKeyInfo(x509Credential));

			logoutResponse.setSignature(signature);

			// Marshall and Sign
			SamlHelper.marshallObject(logoutResponse);
			Signer.signObject(signature);

		} catch (SignatureException | InitializationException | InternalException | MarshallingException e) {
			log.error("Signing of '" + logoutResponse.getID() + "' failed", e);
		}
		return logoutResponse;
	}
}
