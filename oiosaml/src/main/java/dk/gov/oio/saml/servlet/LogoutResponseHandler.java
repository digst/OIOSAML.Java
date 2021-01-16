package dk.gov.oio.saml.servlet;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.StatusCode;

import dk.gov.oio.saml.config.Configuration;
import dk.gov.oio.saml.service.OIOSAML3Service;
import dk.gov.oio.saml.servlet.ErrorHandler.ERROR_TYPE;
import dk.gov.oio.saml.util.ExternalException;
import dk.gov.oio.saml.util.InternalException;
import dk.gov.oio.saml.util.LoggingUtil;
import dk.gov.oio.saml.util.StringUtil;

public class LogoutResponseHandler extends SAMLHandler {

    @Override
    public void handleGet(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws IOException, ExternalException, InternalException {
        MessageContext<SAMLObject> context = decodeGet(httpServletRequest);

        handle(httpServletRequest, httpServletResponse, context);
    }

	@Override
    public void handlePost(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ExternalException, InternalException, IOException {
    	MessageContext<SAMLObject> context = decodePost(httpServletRequest);

        handle(httpServletRequest, httpServletResponse, context);
    }
	
    private void handle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, MessageContext<SAMLObject> context) throws IOException, ExternalException, InternalException {
        LogoutResponse logoutResponse = getSamlObject(context, LogoutResponse.class);

        // Log response
        LoggingUtil.logLogoutResponse(logoutResponse, "Incoming");

        String statusCode = null;
        String statusMessage = null;
        if (logoutResponse.getStatus() != null) {
        	if (logoutResponse.getStatus().getStatusCode() != null) {
        		statusCode = logoutResponse.getStatus().getStatusCode().getValue();
        	}
        	
        	if (logoutResponse.getStatus().getStatusMessage() != null) {
        		statusMessage = logoutResponse.getStatus().getStatusMessage().getMessage();
        	}
        }
        
		// Check if it was a success
		if (StatusCode.SUCCESS.equals(statusCode)) {
			Configuration config = OIOSAML3Service.getConfig();			
			String url = StringUtil.getUrl(httpServletRequest, config.getLogoutPage());

			httpServletResponse.sendRedirect(url);
		}
		else {
			ErrorHandler.handle(httpServletRequest, httpServletResponse, ERROR_TYPE.LOGOUT_ERROR, "Logout failed - response from IdP: " + statusCode + " / " + statusMessage);

			return;
		}
	}
}
