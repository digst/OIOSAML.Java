package dk.gov.oio.saml.servlet;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.core.config.InitializationException;

import dk.gov.oio.saml.config.Configuration;
import dk.gov.oio.saml.service.OIOSAML3Service;
import dk.gov.oio.saml.util.Constants;
import dk.gov.oio.saml.util.InternalException;
import dk.gov.oio.saml.util.StringUtil;

public class ErrorHandler extends SAMLHandler {
    private String errorPage = "<html><body><h3>Error</h3><p>An unexpected error occurred.</p><p>{TYPE}</p><p>{MESSAGE}</p></body></html>";
    public enum ERROR_TYPE { LOGOUT_ERROR, CONFIGURATION_ERROR, EXCEPTION };

    @Override
    public void handleGet(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws IOException, InitializationException, InternalException {
        Configuration config = OIOSAML3Service.getConfig();
        if (StringUtil.isNotEmpty(config.getErrorPage())) {
            String url = StringUtil.getUrl(httpServletRequest, config.getErrorPage());

            httpServletResponse.sendRedirect(url);
            return;
        }

        httpServletResponse.setContentType("text/html");
        
        String page = errorPage.replace("{TYPE}", (String) httpServletRequest.getSession().getAttribute(Constants.SESSION_ERROR_TYPE))
                                .replace("{MESSAGE}", (String) httpServletRequest.getSession().getAttribute(Constants.SESSION_ERROR_MESSAGE));

        httpServletResponse.getWriter().print(page);
    }

    @Override
    public void handlePost(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
        throw new UnsupportedOperationException("POST not allowed");
    }

    public static void handle(HttpServletRequest request, HttpServletResponse response, ERROR_TYPE type, String message) throws IOException {
        Configuration config = OIOSAML3Service.getConfig();
        request.getSession().setAttribute(Constants.SESSION_ERROR_MESSAGE, message);
        request.getSession().setAttribute(Constants.SESSION_ERROR_TYPE, type.toString());

        response.sendRedirect(StringUtil.getUrl(request,String.format("/%s/%s",config.getServletRoutingPathPrefix(),config.getServletRoutingPathSuffixError())));
    }
}
