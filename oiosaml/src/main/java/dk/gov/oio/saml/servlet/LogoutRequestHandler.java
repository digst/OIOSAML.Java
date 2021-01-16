package dk.gov.oio.saml.servlet;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.opensaml.core.config.InitializationException;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;

import dk.gov.oio.saml.config.Configuration;
import dk.gov.oio.saml.service.IdPMetadataService;
import dk.gov.oio.saml.service.LogoutRequestService;
import dk.gov.oio.saml.service.LogoutResponseService;
import dk.gov.oio.saml.service.OIOSAML3Service;
import dk.gov.oio.saml.util.Constants;
import dk.gov.oio.saml.util.ExternalException;
import dk.gov.oio.saml.util.InternalException;
import dk.gov.oio.saml.util.LoggingUtil;
import dk.gov.oio.saml.util.StringUtil;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

public class LogoutRequestHandler extends SAMLHandler {
    private static final Logger log = Logger.getLogger(LogoutRequestHandler.class);

    @Override
    public void handleGet(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws IOException, ExternalException, InternalException {
        if (log.isDebugEnabled()) {
            log.debug("Handling LogoutRequest");
        }

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
                if (log.isDebugEnabled()) {
                    log.debug("Session invalidated");
                }

                try {
                    String location = IdPMetadataService.getInstance().getLogoutEndpoint().getLocation();
                    MessageContext<SAMLObject> messageContext = LogoutRequestService.createMessageWithLogoutRequest(nameId, nameIdFormat, location, index);

                    if (log.isDebugEnabled()) {
                        log.debug("Sending LogoutRequest");
                    }

                    LoggingUtil.logLogoutRequest(getSamlObject(messageContext, LogoutRequest.class), "Outgoing");
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

        LoggingUtil.logLogoutRequest(logoutRequest, "Incoming");

        // Validate logout request, we log the user out not matter what, but we should log if the request is wrong

        // Delete session
        httpServletRequest.getSession().invalidate();
        if (log.isDebugEnabled()) {
            log.debug("Session invalidated");
        }

        // Create LogoutResponse
        try {
            IdPMetadataService metadataService = IdPMetadataService.getInstance();
            String logoutResponseEndpoint = metadataService.getLogoutResponseEndpoint(); // Has to be from the specific IdP that verified the user
            MessageContext<SAMLObject> messageContext = LogoutResponseService.createMessageWithLogoutResponse(logoutRequest, logoutResponseEndpoint);

            if (log.isDebugEnabled()) {
                log.debug("Sending LogoutResponse");
            }

            LoggingUtil.logLogoutResponse(getSamlObject(messageContext, LogoutResponse.class), "Outgoing");
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
