package dk.gov.oio.saml.servlet;

import java.io.IOException;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import dk.gov.oio.saml.util.*;
import org.opensaml.core.xml.io.MarshallingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.opensaml.core.config.InitializationException;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.saml2.core.LogoutRequest;

import dk.gov.oio.saml.config.Configuration;
import dk.gov.oio.saml.service.IdPMetadataService;
import dk.gov.oio.saml.service.LogoutRequestService;
import dk.gov.oio.saml.service.LogoutResponseService;
import dk.gov.oio.saml.service.OIOSAML3Service;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.w3c.dom.Element;

public class LogoutRequestHandler extends SAMLHandler {
    private static final Logger log = LoggerFactory.getLogger(LogoutRequestHandler.class);

    @Override
    public void handleGet(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws IOException, ExternalException, InternalException {
        log.debug("Handling LogoutRequest");

        // Find out if this is SP or IdP Initiated
        String samlRequest = httpServletRequest.getParameter("SAMLRequest");
        if (samlRequest == null || samlRequest.isEmpty()) {
            // SP initiated, generate logoutRequest and send to IdP

        	boolean authenticated = "true".equals(httpServletRequest.getSession().getAttribute(Constants.SESSION_AUTHENTICATED));
            String nameId = (String) httpServletRequest.getSession().getAttribute(Constants.SESSION_NAME_ID);
            String nameIdFormat = (String) httpServletRequest.getSession().getAttribute(Constants.SESSION_NAME_ID_FORMAT);
            String index = (String) httpServletRequest.getSession().getAttribute(Constants.SESSION_SESSION_INDEX);
            httpServletRequest.getSession().invalidate();

            // Send LogoutRequest to IdP only if the session actually has an authenticated user on it
            if (authenticated) {
                log.debug("Session invalidated");

                try {
                    String location = IdPMetadataService.getInstance().getLogoutEndpoint().getLocation();
                    MessageContext<SAMLObject> messageContext = LogoutRequestService.createMessageWithLogoutRequest(nameId, nameIdFormat, location, index);
                    LogoutRequest logoutRequest = getSamlObject(messageContext, LogoutRequest.class);

                    log.info("Outgoing LogoutRequest - ID:'{}' Issuer:'{}' IssueInstant:'{}' SessionIndexes:'{}' Destination:'{}'",
                            logoutRequest.getID(),
                            logoutRequest.getIssuer() != null ?
                                    logoutRequest.getIssuer().getValue() : "",
                            logoutRequest.getIssueInstant() != null ?
                                    logoutRequest.getIssueInstant().toString() : "",
                            logoutRequest.getSessionIndexes()
                                    .stream()
                                    .map(sessionIndex -> sessionIndex.getSessionIndex())
                                    .collect(Collectors
                                            .joining(", ", "[", "]")),
                            logoutRequest.getDestination());

                    sendGet(httpServletResponse, messageContext);
                    return;
                }
                catch (InitializationException | ComponentInitializationException | MessageEncodingException e) {
                    throw new InternalException(e);
                }
            }

            // if not logged in, just forward to front-page
			Configuration config = OIOSAML3Service.getConfig();
			String url = StringUtil.getUrl(httpServletRequest, config.getLogoutPage());			

            log.warn("User not logged in, redirecting to " + url);
			httpServletResponse.sendRedirect(url);
            return;
        }

        // IdP Initiated, generate response
        MessageContext<SAMLObject> context = decodeGet(httpServletRequest);
        LogoutRequest logoutRequest = getSamlObject(context, LogoutRequest.class);

        log.info("Incoming LogoutRequest - ID:'{}' Issuer:'{}' IssueInstant:'{}' SessionIndexes:'{}' Destination:'{}'",
                logoutRequest.getID(),
                logoutRequest.getIssuer() != null ?
                        logoutRequest.getIssuer().getValue() : "",
                logoutRequest.getIssueInstant() != null ?
                        logoutRequest.getIssueInstant().toString() : "",
                logoutRequest.getSessionIndexes()
                        .stream()
                        .map(sessionIndex -> sessionIndex.getSessionIndex())
                        .collect(Collectors
                                .joining(", ", "[", "]")),
                logoutRequest.getDestination());


        // Validate logout request, we log the user out not matter what, but we should log if the request is wrong

        // Delete session
        httpServletRequest.getSession().invalidate();
        log.debug("Session invalidated");

        // Create LogoutResponse
        try {
            IdPMetadataService metadataService = IdPMetadataService.getInstance();
            String logoutResponseEndpoint = metadataService.getLogoutResponseEndpoint(); // Has to be from the specific IdP that verified the user
            MessageContext<SAMLObject> messageContext = LogoutResponseService.createMessageWithLogoutResponse(logoutRequest, logoutResponseEndpoint);

            try {
                Element element = SamlHelper.marshallObject(logoutRequest);
                log.debug("LogoutRequest: {}", StringUtil.elementToString(element));
            } catch (MarshallingException e) {
                log.error("Could not marshall LogoutRequest for logging purposes");
            }

            log.info("Outgoing LogoutRequest - ID:'{}' Issuer:'{}' IssueInstant:'{}' SessionIndexes:'{}' Destination:'{}'",
                    logoutRequest.getID(),
                    logoutRequest.getIssuer() != null ?
                            logoutRequest.getIssuer().getValue() : "",
                    logoutRequest.getIssueInstant() != null ?
                            logoutRequest.getIssueInstant().toString() : "",
                    logoutRequest.getSessionIndexes()
                            .stream()
                            .map(sessionIndex -> sessionIndex.getSessionIndex())
                            .collect(Collectors
                                    .joining(", ", "[", "]")),
                    logoutRequest.getDestination());

            sendPost(httpServletResponse, messageContext);
		}
		catch (InitializationException | ComponentInitializationException | MessageEncodingException e) {
			throw new InternalException(e);
		}
    }

    @Override
    public void handlePost(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ExternalException, InternalException, IOException {
        handleGet(httpServletRequest, httpServletResponse);
    }
}
