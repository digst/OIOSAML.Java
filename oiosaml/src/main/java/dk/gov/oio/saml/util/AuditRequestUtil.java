package dk.gov.oio.saml.util;

import dk.gov.oio.saml.audit.AuditService;
import dk.gov.oio.saml.service.OIOSAML3Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.Objects;

/**
 * Utility class for creating content from the servlet request for the audit log.
 */
public class AuditRequestUtil {
    private static final Logger log = LoggerFactory.getLogger(AuditRequestUtil.class);

    /**
     * Lookup an attribute with the name parameter on the request.
     *
     * @param request HTTP servlet request
     * @param parameter Parameter that is looked up on the request.
     *                  <parameter> ::= <protocol>:<attribute>
     *                  <protocol> ::= <query> | <header> | <cookie> | <session> | <request>
     *                  <attribute> ::= Name of an attribute accessible from the selected protocol.
     *                  <query> ::=	Access to GET and Form POST query parameters/attributes.
     *                  <header> ::= Access to request Header names, as parameters/attributes.
     *                  <cookie> ::= Access to request Cookie names, as parameters/attributes.
     *                  <session> ::= Access to session values i.e. to access SessionId for logging.
     *                  <request> ::= remoteHost | remoteAddr | remotePort | remoteUser
     *                  Ex. "header:User-Agent".
     * @param defaultValue default value if the parameter is not found
     * @return Attribute value from lookup or provided default value
     */
    public static String getAttributeFromRequest(HttpServletRequest request, String parameter, String defaultValue) {
        if (StringUtil.isEmpty(parameter)) {
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
                return getQueryAttributeFromRequest(request, name[1], defaultValue);
            case "cookie":
                return getCookieAttributeFromRequest(request, name[1], defaultValue);
            case "request":
                return getRequestAttributeFromRequest(request, name[1], defaultValue);
            default:
                log.error("Custom parameter protocol '{}' is malformed, should be [request|query|header|cookie|session]",name[0]);
        }
        return defaultValue;
    }

    private static String getQueryAttributeFromRequest(HttpServletRequest request, String parameter, String defaultValue) {
        String[] parameterValues = request.getParameterValues(parameter);
        return (null != parameterValues && parameterValues.length > 0)?
                String.join(",", parameterValues) : defaultValue;
    }

    private static String getCookieAttributeFromRequest(HttpServletRequest request, String parameter, String defaultValue) {
        for (Cookie cookie : request.getCookies()) {
            if (cookie.getName().equals(parameter)) {
                return Objects.toString(cookie.getValue(),defaultValue);
            }
        }
        return defaultValue;
    }

    private static String getRequestAttributeFromRequest(HttpServletRequest request, String parameter, String defaultValue) {
        switch (parameter) {
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
                log.error("Request parameter '{}' is missing, should be [remoteHost|remoteAddr|remotePort|remoteUser]",parameter);
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
