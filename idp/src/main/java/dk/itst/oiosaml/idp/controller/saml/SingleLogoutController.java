package dk.itst.oiosaml.idp.controller.saml;

import dk.itst.oiosaml.idp.service.HTTPRedirectService;
import dk.itst.oiosaml.idp.service.ValidationService;
import lombok.extern.log4j.Log4j2;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpServletRequest;

@Log4j2
@Controller
public class SingleLogoutController {

    @Autowired
    private ValidationService validationService;

    @Autowired
    private HTTPRedirectService httpRedirectService;

    @GetMapping("/saml/slo")
    public String sloEndpoint(HttpServletRequest request) {
        MessageContext<SAMLObject> messageContext = httpRedirectService.getMessageContext(request);

        if (messageContext == null) {
            log.warn("messageContext is null, rejecting request");
            return "saml/error";
        }

        LogoutRequest logoutRequest = (LogoutRequest) messageContext.getMessage();
        if (logoutRequest == null) {
            log.warn("logoutRequest is null, rejecting request");
            return "saml/error";
        }

        boolean validate = validationService.validate(request, messageContext);
        if (!validate) {
            return "login/login";
        }

        return "login/login";
    }
}
