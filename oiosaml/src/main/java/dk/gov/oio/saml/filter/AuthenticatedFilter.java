package dk.gov.oio.saml.filter;

import java.io.IOException;
import java.util.Enumeration;
import java.util.HashMap;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import dk.gov.oio.saml.config.Configuration;
import dk.gov.oio.saml.service.OIOSAML3Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPRedirectDeflateEncoder;
import org.opensaml.saml.saml2.core.AuthnRequest;

import dk.gov.oio.saml.model.NSISLevel;
import dk.gov.oio.saml.service.AuthnRequestService;
import dk.gov.oio.saml.session.AssertionWrapper;
import dk.gov.oio.saml.session.AssertionWrapperHolder;
import dk.gov.oio.saml.session.AuthnRequestWrapper;
import dk.gov.oio.saml.util.Constants;
import dk.gov.oio.saml.util.InternalException;
import dk.gov.oio.saml.util.LoggingUtil;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

public class    AuthenticatedFilter implements Filter {
    private static final Logger log = LoggerFactory.getLogger(AuthenticatedFilter.class);
    private boolean isPassive, forceAuthn;
    private String attributeProfile;
    private NSISLevel requiredNsisLevel = NSISLevel.NONE;
    
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    	HashMap<String, String> config = getConfig(filterConfig);
        
    	String isPassiveStr = config.get(Constants.IS_PASSIVE);
    	String isForceAuthnStr = config.get(Constants.FORCE_AUTHN);

        isPassive = (isPassiveStr != null) ? Boolean.parseBoolean(isPassiveStr) : false;
        forceAuthn = (isForceAuthnStr != null) ? Boolean.parseBoolean(isForceAuthnStr) : false;

        if (isPassive && forceAuthn) {
        	log.warn("IsPassive and forceAuthn Cannot both be true");
        }
        
        try {
            String requiredLevelString = config.get(Constants.REQUIRED_NSIS_LEVEL);
            if (requiredLevelString != null) {
                requiredNsisLevel = NSISLevel.valueOf(requiredLevelString);
            }
        }
        catch (Exception ex) {
            log.warn("Unknown required NSIS level in configuration: " + requiredNsisLevel);
        }
        
        attributeProfile = config.get(Constants.ATTRIBUTE_PROFILE);
        if (attributeProfile != null && (!Constants.ATTRIBUTE_PROFILE_PERSON.equals(attributeProfile) && !Constants.ATTRIBUTE_PROFILE_PROFESSIONAL.equals(attributeProfile))) {
            log.warn("AttributeProfile should be either null, " + Constants.ATTRIBUTE_PROFILE_PERSON + " or " + Constants.ATTRIBUTE_PROFILE_PROFESSIONAL);
        }
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        
        if (log.isDebugEnabled()) {
            log.debug("AuthenticatedFilter invoked by endpoint: '" + req.getContextPath() + req.getServletPath() + "'");
        }

        HttpSession session = req.getSession();

        try {
            // default: not logged in, and no authenticated NSIS level
            boolean authenticated = false;
            NSISLevel authenticatedNsisLevel = tryExtractNSISLevel(session, NSISLevel.NONE);
            String authenticatedAssuranceLevel = tryExtractAssuranceLevel(session);

            // Get current authenticated and NSIS level states from session
            Object attribute = session.getAttribute(Constants.SESSION_AUTHENTICATED);
            if (attribute != null && "true".equals(attribute)) {
                authenticated = true;
            }

            if (log.isDebugEnabled()) {
                log.debug("Current NSIS Level on session: " + authenticatedNsisLevel + ", Required NSIS Level: " + requiredNsisLevel);
            }

            // Is the user authenticated, and at the required level?
            if (!authenticated || !isAssuranceSufficient(requiredNsisLevel, authenticatedNsisLevel, authenticatedAssuranceLevel)) {
                if (log.isDebugEnabled()) {
                    log.debug("Filter config: isPassive: " + isPassive + ", forceAuthn: " + forceAuthn);
                }

                AuthnRequestService authnRequestService = AuthnRequestService.getInstance();

                String reqPath = req.getRequestURI();
                if(req.getQueryString() != null) {
                    reqPath += "?" + req.getQueryString();
                }

                req.getSession().setAttribute(Constants.SESSION_REQUESTED_PATH, reqPath);
                MessageContext<SAMLObject> authnRequest = authnRequestService.createMessageWithAuthnRequest(isPassive, forceAuthn, requiredNsisLevel, attributeProfile);
                sendAuthnRequest(req, res, authnRequest, requiredNsisLevel);
			}
			else {
				try {
					putAssertionOnThreadLocal(session);
	
					// User already authenticated to the correct level
	                chain.doFilter(req, res);
				}
				finally {
					removeAssertionFromThreadLocal();
				}
            }
		}
		catch (Exception e) {
			log.warn("Unexpected error in authentication filter", e);

			throw new ServletException(e);
		}
    }

    private NSISLevel tryExtractNSISLevel(HttpSession session, NSISLevel defaultValue) {
        NSISLevel authenticatedNsisLevel = defaultValue;

        Object attribute = session.getAttribute(Constants.SESSION_NSIS_LEVEL);
        if (attribute != null) {
            try {
                authenticatedNsisLevel = (NSISLevel) attribute;
            }
            catch (Exception ex) {
                log.warn("Unknown NSIS level on session: " + attribute);
            }
        }

        return authenticatedNsisLevel;
    }

    private String tryExtractAssuranceLevel(HttpSession session) {
        Object attribute = session.getAttribute(Constants.SESSION_ASSURANCE_LEVEL);
        if(!(attribute instanceof String)) {
            return null;
        }

        return (String) attribute;
    }

    private boolean isAssuranceSufficient(NSISLevel requiredNsisLevel, NSISLevel authenticatedNsisLevel, String authenticatedAssuranceLevel) {
        Configuration configuration = OIOSAML3Service.getConfig();
        // We do not have anything but the old AssuranceLevel
        if(configuration.isAssuranceLevelAllowed() && authenticatedAssuranceLevel != null) {
            Integer i;
            try {
                i = Integer.parseInt(authenticatedAssuranceLevel);
            } catch (Exception ex) {
                return false;
            }

            return requiredNsisLevel.getAssuranceLevel() <= i;
        }

        return requiredNsisLevel.equalOrLesser(authenticatedNsisLevel);
    }

	@Override
    public void destroy() {
		;
    }

    private void removeAssertionFromThreadLocal() {
    	AssertionWrapperHolder.clear();
	}

	private void putAssertionOnThreadLocal(HttpSession session) {
        Object assertionObject = session.getAttribute(Constants.SESSION_ASSERTION);
        if (assertionObject != null && assertionObject instanceof AssertionWrapper) {                    
            AssertionWrapperHolder.set((AssertionWrapper) assertionObject);

            if (log.isDebugEnabled()) {
                log.debug("Saved Wrapped Assertion to ThreadLocal");
            }
        }
        else {
        	log.warn("No assertion available on session");
        }
	}

    private void sendAuthnRequest(HttpServletRequest req, HttpServletResponse res, MessageContext<SAMLObject> authnRequest, NSISLevel requestedNsisLevel) throws InternalException {
        if (log.isDebugEnabled()) {
            LoggingUtil.logAuthnRequest((AuthnRequest) authnRequest.getMessage());
        }

        // Save authnRequest on session
        HttpSession session = req.getSession();
        session.setAttribute(Constants.SESSION_AUTHN_REQUEST, new AuthnRequestWrapper((AuthnRequest) authnRequest.getMessage(), requiredNsisLevel));

        // Deflating and sending the message
        HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
        encoder.setMessageContext(authnRequest);
        encoder.setHttpServletResponse(res);

        try {
            encoder.initialize();
            encoder.encode();
        }
        catch (ComponentInitializationException | MessageEncodingException e) {
            throw new InternalException("Failed sending AuthnRequest", e);
        }
    }

    private HashMap<String, String> getConfig(FilterConfig filterConfig) {
        HashMap<String, String> configMap = new HashMap<>();
        Enumeration<String> keys = filterConfig.getInitParameterNames();
        while (keys.hasMoreElements()) {
            String key = keys.nextElement();
            String value = filterConfig.getInitParameter(key);
            configMap.put(key, value);
        }

        return configMap;
    }
}
