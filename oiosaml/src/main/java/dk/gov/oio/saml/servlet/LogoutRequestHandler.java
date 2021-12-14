package dk.gov.oio.saml.servlet;

import java.io.IOException;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import dk.gov.oio.saml.session.AssertionWrapper;
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
    public void handleGet(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ExternalException, InternalException, IOException {
        log.debug("Handling HTTP LogoutRequest");
        if (isServiceProviderRequest(httpServletRequest)) {
            handleServiceProviderRequest( httpServletRequest,  httpServletResponse);
            return;
        }

        // IdP Initiated, generate response
        MessageContext<SAMLObject> context = decodeGet(httpServletRequest);
        LogoutRequest logoutRequest = getSamlObject(context, LogoutRequest.class);

        MessageContext<SAMLObject> outgoingMessage = handleRequest(httpServletRequest, logoutRequest);
        try {
            sendPost(httpServletResponse, outgoingMessage);
        } catch (ComponentInitializationException | MessageEncodingException e) {
            throw new InternalException(e);
        }
    }

    @Override
    public void handlePost(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ExternalException, InternalException, IOException {
        handleGet(httpServletRequest, httpServletResponse);
    }

    @Override
    public void handleSOAP(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ExternalException, InternalException {
        log.debug("Handling SOAP LogoutRequest");
        // IdP Initiated, generate response
        MessageContext<SAMLObject> context = decodeSOAP(httpServletRequest);
        LogoutRequest logoutRequest = getSamlObject(context, LogoutRequest.class);

        MessageContext<SAMLObject> outgoingMessage = handleRequest(httpServletRequest, logoutRequest);
        try {
            sendSOAP(httpServletResponse, outgoingMessage);
        } catch (ComponentInitializationException | MessageEncodingException e) {
            throw new InternalException(e);
        }
    }

    private boolean invalidateUserSession(HttpServletRequest httpServletRequest) {
        log.debug("Invalidate user session");

        AssertionWrapper assertion = (AssertionWrapper) httpServletRequest.getSession().getAttribute(Constants.SESSION_ASSERTION);
        boolean authenticated = isAuthenticated(httpServletRequest);

        log.info("Authenticated: {}", authenticated);

        OIOSAML3Service.getAuditService().auditLog(AuditRequestUtil
                .createBasicAuditBuilder(httpServletRequest, "SLO1", "ServiceProviderLogout")
                .withAuthnAttribute("SP_SESSION_ID", getUserSessionId(httpServletRequest))
                .withAuthnAttribute("ASSERTION_ID", (null != assertion)? assertion.getID():"")
                .withAuthnAttribute("REQUEST", isAuthenticated(httpServletRequest) ? "VALID":"INVALID"));

        // Invalidate users session

        // TODO: This should invalidate the OIOSAML session (missing in current implementation)

        // Invalidate current http session - remove all data
        httpServletRequest.getSession().invalidate();

        return authenticated;
    }

    private void handleServiceProviderRequest(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws IOException, ExternalException, InternalException {
        log.debug("Handling ServiceProvider LogoutRequest");

        // SP initiated, generate logoutRequest and send to IdP
        if (!invalidateUserSession(httpServletRequest)) {

            // if not logged in, just forward to front-page
            Configuration config = OIOSAML3Service.getConfig();
            String url = StringUtil.getUrl(httpServletRequest, config.getLogoutPage());

            log.warn("User not logged in, redirecting to " + url);
            httpServletResponse.sendRedirect(url);
            return;
        }

        // Send LogoutRequest to IdP only if the session actually has an authenticated user on it

        log.debug("Send LogoutRequest to IdP");
        try {
            HttpSession session = httpServletRequest.getSession();
            String nameId = (String) session.getAttribute(Constants.SESSION_NAME_ID);
            String nameIdFormat = (String) session.getAttribute(Constants.SESSION_NAME_ID_FORMAT);
            String index = (String) session.getAttribute(Constants.SESSION_SESSION_INDEX);
            String location = IdPMetadataService.getInstance().getLogoutEndpoint().getLocation();

            MessageContext<SAMLObject> messageContext = LogoutRequestService.createMessageWithLogoutRequest(nameId, nameIdFormat, location, index);
            LogoutRequest logoutRequest = getSamlObject(messageContext, LogoutRequest.class);

            OIOSAML3Service.getAuditService().auditLog(AuditRequestUtil
                    .createBasicAuditBuilder(httpServletRequest, "SLO2", "OutgoingLogoutRequest")
                    .withAuthnAttribute("SP_SESSION_ID", getUserSessionId(httpServletRequest))
                    .withAuthnAttribute("LOGOUT_REQUEST_ID", logoutRequest.getID())
                    .withAuthnAttribute("LOGOUT_REQUEST_DESTINATION", logoutRequest.getDestination()));

            // Log LogoutRequest
            try {
                Element element = SamlHelper.marshallObject(logoutRequest);
                log.debug("LogoutRequest: {}", StringUtil.elementToString(element));
            } catch (MarshallingException e) {
                log.error("Could not marshall LogoutRequest for logging purposes");
            }
            log.info("Outgoing LogoutRequest - ID:'{}' Issuer:'{}' IssueInstant:'{}' SessionIndexes:'{}' Destination:'{}'",
                    logoutRequest.getID(),
                    getIssuer(logoutRequest),
                    getIssueInstant(logoutRequest),
                    getSessionIndexes(logoutRequest),
                    logoutRequest.getDestination());

            sendGet(httpServletResponse, messageContext);
        }
        catch (InitializationException | ComponentInitializationException | MessageEncodingException e) {
            throw new InternalException(e);
        }
    }

    private MessageContext<SAMLObject> handleRequest(HttpServletRequest httpServletRequest, LogoutRequest logoutRequest) throws ExternalException, InternalException {
        log.debug("Handling LogoutRequest");
        AssertionWrapper assertion = (AssertionWrapper) httpServletRequest.getSession().getAttribute(Constants.SESSION_ASSERTION);

        // Log LogoutRequest
        try {
            Element element = SamlHelper.marshallObject(logoutRequest);
            log.debug("LogoutRequest: {}", StringUtil.elementToString(element));
        } catch (MarshallingException e) {
            log.error("Could not marshall LogoutRequest for logging purposes");
        }
        log.info("Incoming LogoutRequest - ID:'{}' Issuer:'{}' IssueInstant:'{}' SessionIndexes:'{}' Destination:'{}'",
                logoutRequest.getID(),
                getIssuer(logoutRequest),
                getIssueInstant(logoutRequest),
                getSessionIndexes(logoutRequest),
                logoutRequest.getDestination());

        OIOSAML3Service.getAuditService().auditLog(AuditRequestUtil
                .createBasicAuditBuilder(httpServletRequest, "SLO4", "IncomingLogoutRequest")
                .withAuthnAttribute("SP_SESSION_ID", getUserSessionId(httpServletRequest))
                .withAuthnAttribute("ASSERTION_ID", (null != assertion) ? assertion.getID():"")
                .withAuthnAttribute("SUBJECT_NAME_ID", (null != assertion) ? assertion.getSubjectNameId():"")
                .withAuthnAttribute("LOGOUT_REQUEST_ID", logoutRequest.getID())
                .withAuthnAttribute("SIGNATURE_REFERENCE", logoutRequest.getSignatureReferenceID())
                .withAuthnAttribute("LOGOUT_REQUEST_DESTINATION", logoutRequest.getDestination())
                .withAuthnAttribute("REQUEST", (isAuthenticated(httpServletRequest)) ? "VALID":"INVALID"));

        if (invalidateUserSession(httpServletRequest)) {
            OIOSAML3Service.getAuditService().auditLog(AuditRequestUtil
                    .createBasicAuditBuilder(httpServletRequest, "SLO4", "InvalidatedSession")
                    .withAuthnAttribute("SP_SESSION_ID", getUserSessionId(httpServletRequest)));
        }

        // Create LogoutResponse
        try {
            IdPMetadataService metadataService = IdPMetadataService.getInstance();
            String logoutResponseEndpoint = metadataService.getLogoutResponseEndpoint(); // Has to be from the specific IdP that verified the user
            MessageContext<SAMLObject> messageContext = LogoutResponseService.createMessageWithLogoutResponse(logoutRequest, logoutResponseEndpoint);

            // Log LogoutRequest
            try {
                Element element = SamlHelper.marshallObject(logoutRequest);
                log.debug("LogoutRequest: {}", StringUtil.elementToString(element));
            } catch (MarshallingException e) {
                log.error("Could not marshall LogoutRequest for logging purposes");
            }
            log.info("Outgoing LogoutRequest - ID:'{}' Issuer:'{}' IssueInstant:'{}' SessionIndexes:'{}' Destination:'{}'",
                    logoutRequest.getID(),
                    getIssuer(logoutRequest),
                    getIssueInstant(logoutRequest),
                    getSessionIndexes(logoutRequest),
                    logoutRequest.getDestination());

            return messageContext;
        }
        catch (InitializationException e) {
            throw new InternalException(e);
        }
    }

    private boolean isAuthenticated(HttpServletRequest httpServletRequest) {

        // TODO: This should return true if there is an actual OIOSAML session (missing in current implementation)

        return "true".equals(httpServletRequest.getSession().getAttribute(Constants.SESSION_AUTHENTICATED));
    }

    private boolean isServiceProviderRequest(HttpServletRequest httpServletRequest) {
        String samlRequest = httpServletRequest.getParameter("SAMLRequest");
        return  samlRequest == null || samlRequest.isEmpty();
    }

    private String getUserSessionId(HttpServletRequest httpServletRequest) {

        // TODO: This should return an actual OIOSAML session id (missing in current implementation)

        HttpSession session = httpServletRequest.getSession();
        return session.getId();
    }

    private String getIssuer(LogoutRequest logoutRequest) {
        return logoutRequest.getIssuer() != null ?
                logoutRequest.getIssuer().getValue() : "";
    }

    private String getIssueInstant(LogoutRequest logoutRequest) {
        return logoutRequest.getIssueInstant() != null ?
                logoutRequest.getIssueInstant().toString() : "";
    }

    private String getSessionIndexes(LogoutRequest logoutRequest) {
        return logoutRequest.getSessionIndexes()
                .stream()
                .map(sessionIndex -> sessionIndex.getSessionIndex())
                .collect(Collectors
                        .joining(", ", "[", "]"));
    }
}
