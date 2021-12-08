package dk.gov.oio.saml.util;

import dk.gov.oio.saml.audit.AuditService;
import dk.gov.oio.saml.service.OIOSAML3Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.Objects;

public class RequestUtil {
    private static final Logger log = LoggerFactory.getLogger(RequestUtil.class);

    /**
     * Lookup an attribute with the name parameter on the request.
     *
     * @param request HTTP servlet request
     * @param parameter Parameter that is looked up on the request.
     *                  Parameter MUST have the format [Protocol:Name].
     *                  Protocol MUST be one of: [query|header|cookie|session].
     *                  Name is the attribute name/id.
     *                  Ex. "header:User-Agent".
     * @param defaultValue default value if the parameter is not found
     * @return Attribute value from lookup or provided default value
     */
    public static String getAttributeFromRequest(HttpServletRequest request, String parameter, String defaultValue) {
        if (null == parameter || parameter.length() == 0 ) {
            return defaultValue;
        }
        String[] name = Objects.toString(parameter, "").split(":", 2);

        if (name.length != 2) {
            log.error("Custom request parameter '{}' is malformed, should be '<protocol>:<attribute>'",parameter);
            return defaultValue;
        }

        switch (name[0]) {
            case "header":
                return Objects.toString(request.getHeader(name[1]), defaultValue);
            case "session":
                return Objects.toString(request.getSession().getAttribute(name[1]), defaultValue);
            case "query":
                String[] parameterValues = request.getParameterValues(name[1]);
                return (null != parameterValues && parameterValues.length > 0)?
                        String.join(",", parameterValues) : defaultValue;
            case "cookie": {
                for (Cookie cookie : request.getCookies()) {
                    if (cookie.getName().equals(name[1])) {
                        return Objects.toString(cookie.getValue(),defaultValue);
                    }
                }
                return defaultValue;
            }
            case "request": {
                switch (name[1]) {
                    case "remoteHost" :
                        return Objects.toString(request.getRemoteHost(), defaultValue);
                    case "remoteAddr" :
                        return Objects.toString(request.getRemoteAddr(), defaultValue);
                    case "remotePort" :
                        return Objects.toString(String.valueOf(request.getRemotePort()), defaultValue);
                    case "remoteUser" :
                        return Objects.toString(request.getRemoteUser(), defaultValue);
                    case "sessionId" :
                        return Objects.toString(request.getSession().getId(), defaultValue);
                    default:
                        log.error("Request parameter '{}' is missing, should be [remoteHost|remoteAddr|remotePort|remoteUser]",name[1]);
                }
            }
            default:
                log.error("Custom parameter protocol '{}' is malformed, should be [request|query|header|cookie|session]",name[0]);
        }
        return defaultValue;
    }

    /**
     * Create builder for audit record, initialized with http request values.
     *
     * @param request HTTP servlet request
     * @param action Identifier for the event which is audited
     * @param description Descriptive name for the event which is audited
     * @return Builder for audit record
     */
    public static AuditService.Builder createBasicAuditBuilder(HttpServletRequest request, String action, String description) {
        return new AuditService
                .Builder()
                .withAuthnAttribute("ACTION", action)
                .withAuthnAttribute("DESCRIPTION", description)
                .withAuthnAttribute("IP", getAttributeFromRequest(request, OIOSAML3Service.getConfig().getAuditRequestAttributeIP(), request.getRemoteAddr()))
                .withAuthnAttribute("PORT", getAttributeFromRequest(request, OIOSAML3Service.getConfig().getAuditRequestAttributePort(), Objects.toString(request.getRemotePort())))
                .withAuthnAttribute("SESSION_ID", getAttributeFromRequest(request, OIOSAML3Service.getConfig().getAuditRequestAttributeSessionId(), Objects.toString(request.getSession().getId())))
                .withAuthnAttribute("REQUESTED_SESSION_ID", Objects.toString(request.getRequestedSessionId()))
                .withAuthnAttribute("USER", getAttributeFromRequest(request, OIOSAML3Service.getConfig().getAuditRequestAttributeServiceProviderUserId(), Objects.toString(request.getRemoteUser())))
                .withAuthnAttribute("USER-AGENT", getAttributeFromRequest(request, "header:User-Agent",
                        getAttributeFromRequest(request, "header:Sec-Ch-Ua", "None")));

    }
}
