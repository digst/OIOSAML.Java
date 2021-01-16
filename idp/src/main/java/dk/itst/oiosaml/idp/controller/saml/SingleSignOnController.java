package dk.itst.oiosaml.idp.controller.saml;

import java.util.Optional;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.messaging.context.SAMLBindingContext;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPPostEncoder;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.impl.AuthnRequestMarshaller;
import org.opensaml.saml.saml2.core.impl.AuthnRequestUnmarshaller;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.w3c.dom.Element;

import dk.itst.oiosaml.idp.config.Session;
import dk.itst.oiosaml.idp.config.SessionConfig;
import dk.itst.oiosaml.idp.service.HTTPPostService;
import dk.itst.oiosaml.idp.service.HTTPRedirectService;
import dk.itst.oiosaml.idp.service.OpenSAMLHelperService;
import dk.itst.oiosaml.idp.service.ValidationService;
import dk.itst.oiosaml.idp.util.Constants;
import lombok.extern.log4j.Log4j2;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.velocity.VelocityEngine;

@Log4j2
@Controller
public class SingleSignOnController {

    @Autowired
    private ValidationService validationService;

    @Autowired
    private HTTPRedirectService httpRedirectService;

    @Autowired
    private OpenSAMLHelperService samlBuilder;

    @Autowired
    private HTTPPostService httpPostService;

    @Autowired
    private SessionConfig sessionConfig;


    @GetMapping("/saml/sso")
    public String ssoEndpoint(HttpServletRequest request) {
        MessageContext<SAMLObject> messageContext = httpRedirectService.getMessageContext(request);

        if (messageContext == null) {
            log.warn("messageContext is null, rejecting request");
            return "saml/error";
        }

        AuthnRequest authnRequest = (AuthnRequest) messageContext.getMessage();
        if (authnRequest == null) {
            log.warn("authnRequest is null, rejecting request");
            return "saml/error";
        }

        SAMLBindingContext subcontext = messageContext.getSubcontext(SAMLBindingContext.class);
        if (subcontext != null) {
            request.getSession().setAttribute(Constants.RELAY_STATE, subcontext.getRelayState());
        }

        boolean valid = validationService.validate(request, messageContext);
        if (!valid) {
            log.warn("Request not valid, rejecting request");
            return "saml/error";
        }

        // Log-in flow
        AuthnRequestMarshaller marshaller = new AuthnRequestMarshaller();
        try {
            Element marshalledObject = marshaller.marshall(authnRequest);
            request.getSession().setAttribute(Constants.AUTHN_REQUEST, marshalledObject);
        } catch (MarshallingException e) {
            e.printStackTrace();
        }

        boolean requireLogin = true; //TODO for now login is always required.
        if (authnRequest.isForceAuthn() || requireLogin) {
            return "login/login";
        } else {
            return null;
        }
    }

    @PostMapping("/saml/sso")
    public String login(HttpServletRequest request, HttpServletResponse httpServletResponse, @RequestParam("username") String username, @RequestParam("password") String password) {
        try {
            //Login check
            Optional<Session> sessionOptional = sessionConfig.getSessions().stream().filter(session -> session.getUsername().equals(username)).findFirst();
            if (!sessionOptional.isPresent()) {
                log.warn("User " + username + " could not be found");
                return "login/login";
            }

            Session session = sessionOptional.get();
            if (!session.getPassword().equals(password)) {
                log.warn("Login attempt for user " + username + " with invalid password");
                return "login/login";
            }

            // Get AuthnRequest
            Element marshalledObject = (Element) request.getSession().getAttribute(Constants.AUTHN_REQUEST);
            AuthnRequestUnmarshaller unmarshaller = new AuthnRequestUnmarshaller();
            AuthnRequest authnRequest = (AuthnRequest) unmarshaller.unmarshall(marshalledObject);

            // Create Response
            Response response = httpPostService.createResponse(session, authnRequest);

            // Build MessageContext and add response
            MessageContext<SAMLObject> messageContext = new MessageContext<>();
            messageContext.setMessage(response);
            SAMLBindingContext subcontext = messageContext.getSubcontext(SAMLBindingContext.class, true);
            subcontext.setRelayState((String) request.getSession().getAttribute(Constants.RELAY_STATE));

            // Set destination
            SAMLPeerEntityContext peerEntityContext = messageContext.getSubcontext(SAMLPeerEntityContext.class, true);
            SAMLEndpointContext endpointContext = peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);

            SingleSignOnService endpoint = samlBuilder.buildSAMLObject(SingleSignOnService.class);
            endpoint.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
            endpoint.setLocation(authnRequest.getAssertionConsumerServiceURL());

            endpointContext.setEndpoint(endpoint);

            // Encode and send
            HTTPPostEncoder encoder = new HTTPPostEncoder();
            encoder.setHttpServletResponse(httpServletResponse);
            encoder.setMessageContext(messageContext);
            encoder.setVelocityEngine(VelocityEngine.newVelocityEngine());

            encoder.initialize();
            encoder.encode();
            return null;
        } catch (UnmarshallingException | MessageEncodingException | ComponentInitializationException e) {
            log.error("POST: /saml/sso failed", e);
        }

        return "error";
    }
}
