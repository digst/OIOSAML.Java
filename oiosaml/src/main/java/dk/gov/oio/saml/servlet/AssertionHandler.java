package dk.gov.oio.saml.servlet;

import java.io.IOException;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.assertion.AssertionValidationException;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Response;

import dk.gov.oio.saml.config.Configuration;
import dk.gov.oio.saml.model.NSISLevel;
import dk.gov.oio.saml.service.AssertionService;
import dk.gov.oio.saml.service.OIOSAML3Service;
import dk.gov.oio.saml.service.validation.AssertionValidationService;
import dk.gov.oio.saml.session.AssertionWrapper;
import dk.gov.oio.saml.session.AuthnRequestWrapper;
import dk.gov.oio.saml.util.Constants;
import dk.gov.oio.saml.util.ExternalException;
import dk.gov.oio.saml.util.InternalException;
import dk.gov.oio.saml.util.LoggingUtil;
import dk.gov.oio.saml.util.SamlHelper;
import dk.gov.oio.saml.util.StringUtil;

public class AssertionHandler extends SAMLHandler {

    @Override
    public void handleGet(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws IOException {
        throw new UnsupportedOperationException("GET not allowed");
    }

    @Override
    public void handlePost(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ExternalException, InternalException, IOException {
        // Decode request
        MessageContext<SAMLObject> messageContext = decodePost(httpServletRequest);
        SAMLObject samlObject = messageContext.getMessage();

        // Get response object
        if (!(samlObject instanceof Response)) {
            throw new ExternalException("Saml message was not a response");
        }
        Response response = (Response) samlObject;

        // Log response
        LoggingUtil.logResponse(response, "Incoming");

        // Get assertion
        AssertionService assertionService = new AssertionService();
        Assertion assertion = assertionService.getAssertion(response);
        
        // Get AuthnRequest with matching ID (inResponseTo)
        HttpSession session = httpServletRequest.getSession();
        AuthnRequestWrapper authnRequest = (AuthnRequestWrapper) session.getAttribute(Constants.SESSION_AUTHN_REQUEST);
        
        if (authnRequest == null) {
            throw new InternalException("No AuthnRequest found on session");
        }
        
        // Validate
        try {
            AssertionValidationService validationService = new AssertionValidationService();
            validationService.validate(httpServletRequest, messageContext, response, assertion, authnRequest);
		}
		catch (AssertionValidationException e) {
			throw new ExternalException(e);
		}
        finally {
	        // always log Assertion
	        LoggingUtil.logAssertion(assertion);
        }

        // Set NSISLevel to what was provided by the Assertion
        if (assertion.getAttributeStatements() == null || assertion.getAttributeStatements().size() != 1) {
            throw new ExternalException("Assertion AttributeStatements were null or had more than one");
        }

        Map<String, String> attributeMap = SamlHelper.extractAttributeValues(assertion.getAttributeStatements().get(0));
        String loa = attributeMap.get(Constants.LOA);
        String assuranceLevel = attributeMap.get(Constants.ASSURANCE_LEVEL);
        NSISLevel nsisLevel = NSISLevel.getNSISLevelFromLOA(loa, NSISLevel.NONE);

        session.setAttribute(Constants.SESSION_NSIS_LEVEL, nsisLevel);
        if(assuranceLevel != null) {
            session.setAttribute(Constants.SESSION_ASSURANCE_LEVEL, assuranceLevel);
        }

        session.setAttribute(Constants.SESSION_AUTHENTICATED, "true");
        session.setAttribute(Constants.SESSION_SESSION_INDEX, getSessionIndex(assertion));

		AssertionWrapper wrapper = new AssertionWrapper(assertion);
		session.setAttribute(Constants.SESSION_ASSERTION, wrapper);

        NameID nameID = assertion.getSubject().getNameID();
        session.setAttribute(Constants.SESSION_NAME_ID, nameID.getValue());
        session.setAttribute(Constants.SESSION_NAME_ID_FORMAT, nameID.getFormat());

        Object attribute = session.getAttribute(Constants.SESSION_REQUESTED_PATH);

        // If we have a saved requested path on the session redirect to it
        if (attribute != null) {
            String path = (String) attribute;
            httpServletResponse.sendRedirect(path);
            return;
        }

        Configuration config = OIOSAML3Service.getConfig();
    	String url = StringUtil.getUrl(httpServletRequest, config.getLoginPage());
        
        httpServletResponse.sendRedirect(url);
    }

	private String getSessionIndex(Assertion assertion) {
        if (assertion.getAuthnStatements() != null && assertion.getAuthnStatements().size() > 0) {
        	for (AuthnStatement authnStatement : assertion.getAuthnStatements()) {
        		if (authnStatement.getSessionIndex() != null && authnStatement.getSessionIndex().length() > 0) {
        			return authnStatement.getSessionIndex();
        		}
        	}
        }

        return null;
	}
}
