package dk.itst.oiosaml.idp.service;

import dk.itst.oiosaml.idp.util.Constants;
import lombok.extern.log4j.Log4j2;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.binding.security.impl.MessageLifetimeSecurityHandler;
import org.opensaml.saml.common.binding.security.impl.ReceivedEndpointSecurityHandler;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.security.SecurityException;
import org.opensaml.security.crypto.SigningUtil;
import org.opensaml.xmlsec.algorithm.AlgorithmSupport;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.Base64;

@Log4j2
@Service
public class ValidationService {

    @Autowired
    private CredentialService credentialService;

    @Autowired
    private MetadataService metadataService;

    public boolean validate(HttpServletRequest request, MessageContext<SAMLObject> messageContext) {
        log.debug("Started validation");

        try {
            boolean validDestination = validateDestination(request, messageContext);
            boolean validLifetime = validateLifetime(messageContext);
            boolean validSignature = validateSignature(request, messageContext);

            return (validSignature && validDestination && validLifetime);
        } catch (Exception e) {
            log.error("Validation failed", e);
            return false;
        }
    }

    private boolean validateDestination(HttpServletRequest request, MessageContext<SAMLObject> messageContext) {
        log.debug("Started destination validation");
        ReceivedEndpointSecurityHandler endpointSecurityHandler = new ReceivedEndpointSecurityHandler();
        try {
            endpointSecurityHandler.setHttpServletRequest(request);
            endpointSecurityHandler.initialize();
            endpointSecurityHandler.invoke(messageContext);
            endpointSecurityHandler.destroy();
        } catch (ComponentInitializationException | MessageHandlerException e) {
            return false;
        }
        return true;
    }

    private boolean validateLifetime(MessageContext<SAMLObject> messageContext) {
        log.debug("Started message lifetime validation");
        MessageLifetimeSecurityHandler lifetimeHandler = new MessageLifetimeSecurityHandler();
        lifetimeHandler.setClockSkew(60 * 5 * 1000);
        try {
            lifetimeHandler.initialize();
            lifetimeHandler.invoke(messageContext);
            lifetimeHandler.destroy();
        } catch (ComponentInitializationException | MessageHandlerException e) {
            return false;
        }
        return true;
    }

    private boolean validateSignature(HttpServletRequest request, MessageContext<SAMLObject> messageContext) throws CertificateException, SecurityException {
        // Verify Signature
        String queryString = request.getQueryString();
        String signature = request.getParameter("Signature");
        String sigAlg = request.getParameter("SigAlg");

        AuthnRequest authnRequest = (AuthnRequest) messageContext.getMessage();
        PublicKey publicKey = metadataService.getSPSigningKey(authnRequest.getIssuer().getValue());

        return validateSignature(queryString, Constants.SAMLRequest, publicKey, signature, sigAlg);
    }

    private static boolean validateSignature(String queryString, String queryParameter, PublicKey publicKey, String signature, String sigAlg) throws SecurityException {
        log.debug("Started signature validation");

        // Get url string to be verified
        byte[] data = new byte[0];
        data = parseSignedQueryString(queryString, queryParameter).getBytes(StandardCharsets.UTF_8);

        // Decode signature
        byte[] decodedSignature = Base64.getDecoder().decode(signature);
        String jcaAlgorithmID = AlgorithmSupport.getAlgorithmID(sigAlg);

        // Verify signature
        boolean valid = SigningUtil.verify(publicKey, jcaAlgorithmID, decodedSignature, data);
        log.debug(valid ? "Signature successfully validated" : "Signature validation failed");
        return valid;
    }

    private static String parseSignedQueryString(String queryString, String queryParameter) {
        StringBuilder s = new StringBuilder();

        String samlRequestOrResponse = getParameter(queryParameter, queryString);
        String relayState = getParameter("RelayState", queryString);
        String sigAlg = getParameter("SigAlg", queryString);

        s.append(queryParameter);
        s.append("=");
        s.append(samlRequestOrResponse);

        if (relayState != null) {
            s.append("&");
            s.append("RelayState");
            s.append("=");
            s.append(relayState);
        }

        s.append("&");
        s.append("SigAlg");
        s.append("=");
        s.append(sigAlg);

        return s.toString();
    }

    private static String getParameter(String name, String url) {
        String[] parameters = url.split("&");

        for (String parameter : parameters) {
            int pos = parameter.indexOf('=');
            String key = parameter.substring(0, pos);

            if (name.equals(key)) {
                return parameter.substring(pos + 1);
            }
        }

        return null;
    }
}
