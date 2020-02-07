/*
 * The contents of this file are subject to the Mozilla Public 
 * License Version 1.1 (the "License"); you may not use this 
 * file except in compliance with the License. You may obtain 
 * a copy of the License at http://www.mozilla.org/MPL/
 * 
 * Software distributed under the License is distributed on an 
 * "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, either express 
 * or implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 *
 * The Original Code is OIOSAML Java Service Provider.
 * 
 * The Initial Developer of the Original Code is Trifork A/S. Portions 
 * created by Trifork A/S are Copyright (C) 2008 Danish National IT 
 * and Telecom Agency (http://www.itst.dk). All Rights Reserved.
 * 
 * Contributor(s):
 *   Joakim Recht <jre@trifork.com>
 *   Rolf Njor Jensen <rolf@trifork.com>
 *
 */
package dk.itst.oiosaml.sp.service;

import java.io.IOException;
import java.util.Enumeration;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;

import org.apache.commons.configuration.Configuration;
import org.opensaml.saml2.core.Assertion;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.configuration.SAMLConfigurationFactory;
import dk.itst.oiosaml.logging.Audit;
import dk.itst.oiosaml.logging.Logger;
import dk.itst.oiosaml.logging.LoggerFactory;
import dk.itst.oiosaml.logging.Operation;
import dk.itst.oiosaml.sp.AuthenticationHandler;
import dk.itst.oiosaml.sp.PassiveUserAssertion;
import dk.itst.oiosaml.sp.UserAssertion;
import dk.itst.oiosaml.sp.UserAssertionImpl;
import dk.itst.oiosaml.sp.metadata.IdpMetadata.Metadata;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.model.OIOResponse;
import dk.itst.oiosaml.sp.model.RelayState;
import dk.itst.oiosaml.sp.model.validation.AssertionValidator;
import dk.itst.oiosaml.sp.service.util.ArtifactExtractor;
import dk.itst.oiosaml.sp.service.util.Constants;
import dk.itst.oiosaml.sp.service.util.HTTPUtils;
import dk.itst.oiosaml.sp.service.util.HttpSOAPClient;
import dk.itst.oiosaml.sp.service.util.PostResponseExtractor;
import dk.itst.oiosaml.sp.service.util.SOAPClient;
import dk.itst.oiosaml.sp.service.util.Utils;

/**
 * Servlet for receiving SAML asertions from the IdP.
 * 
 * <p>
 * The servlet supports both POST and Artifact binding. POST reception is handled by {@link PostResponseExtractor} while Artifact is handled by {@link ArtifactExtractor}.
 * </p>
 * 
 * <p>
 * Upon reception, SAML responses are validated using {@link OIOResponse#validateResponse(String, java.security.cert.Certificate)}, and the attached signature is also checked.
 * </p>
 * 
 * <p>
 * If the SAML response can be validated, and is a known response, the received assertion is set in the user's session using {@link LoggedInHandler#setAssertion(HttpSession, OIOAssertion)}. The user is then redirected either to the home url, or to the url saved in the session attributes
 * {@link Constants#SESSION_REQUESTURI} and {@link Constants#SESSION_QUERYSTRING}.
 * 
 * @author Joakim Recht <jre@trifork.com>
 * @author Rolf Njor Jensen <rolf@trifork.com>
 */
public class SAMLAssertionConsumerHandler implements SAMLHandler {

	@SuppressWarnings("unused")
	private static final long serialVersionUID = -8417816228519917989L;
	public static final String VERSION = "$Id: SAMLAssertionConsumerHandler.java 2910 2008-05-21 13:07:31Z jre $";

	private static final Logger log = LoggerFactory.getLogger(SAMLAssertionConsumerHandler.class);
	private SOAPClient client;
	private final AssertionValidator validator;

	public SAMLAssertionConsumerHandler(Configuration config) {
		this.validator = (AssertionValidator) Utils.newInstance(config, Constants.PROP_VALIDATOR);
		setSoapClient(new HttpSOAPClient());
	}

	public void setSoapClient(SOAPClient soapClient) {
		client = soapClient;
	}

	public void handlePost(RequestContext ctx) throws IOException, ServletException {
		PostResponseExtractor extractor = new PostResponseExtractor();
		handleSAMLResponse(ctx, extractor.extract(ctx.getRequest()));
	}

	/**
	 * Receive an artifact from the login site and make a back channel call &lt;ArtifactResolve&gt; to the login site in order to obtain the associated {@link OIOAssertion}
	 */
	public void handleGet(RequestContext ctx) throws IOException, ServletException {
		if (ctx.getRequest().getParameter(Constants.SAML_SAMLRESPONSE) != null) {
			handlePost(ctx);
		}
		else {
			ArtifactExtractor extractor = new ArtifactExtractor(ctx.getIdpMetadata(), ctx.getSpMetadata().getEntityID(), client, ctx.getConfiguration().getString(Constants.PROP_RESOLVE_USERNAME), ctx.getConfiguration().getString(Constants.PROP_RESOLVE_PASSWORD),
					ctx.getConfiguration().getBoolean(Constants.PROP_IGNORE_CERTPATH, false));
			handleSAMLResponse(ctx, extractor.extract(ctx.getRequest()));
		}
	}

	private void handleSAMLResponse(RequestContext ctx, OIOResponse response) throws IOException, ServletException {
		Audit.log(Operation.AUTHNREQUEST_SEND, false, response.getInResponseTo(), response.toXML());

		HttpSession session = ctx.getSession();

		if (log.isDebugEnabled()) {
			log.debug("Calling URL.:" + ctx.getRequest().getRequestURI() + "?" + ctx.getRequest().getQueryString());
			log.debug("SessionId..:" + session.getId());
		}

		RelayState relayState = RelayState.fromRequest(ctx.getRequest());
		if (log.isDebugEnabled())
			log.debug("Got relayState..:" + relayState);

		String idpEntityId = response.getOriginatingIdpEntityId(ctx.getSessionHandler());
		if (log.isDebugEnabled())
			log.debug("Received SAML Response from " + idpEntityId + ": " + response.toXML());

		boolean allowPassive = ctx.getConfiguration().getBoolean(Constants.PROP_PASSIVE, false);
		Metadata metadata = ctx.getIdpMetadata().getMetadata(idpEntityId);

		response.validateResponse(ctx.getSpMetadata().getAssertionConsumerServiceLocation(0), metadata.getValidCertificates(), allowPassive);
		response.decryptAssertion(ctx.getCredential(), !ctx.getConfiguration().getBoolean(Constants.PROP_REQUIRE_ENCRYPTION, false));
		response.validateAssertionSignature(metadata.getValidCertificates());

		// if the copySessionListener is active (enabled in web.xml), we can copy attributes from sessions
		// that where orphaned by the SameSite=Lax cookie session through this lookup
		HttpSession oldSession = SAMLConfigurationFactory.getConfiguration().getSameSiteSessionSynchronizer().getSession(response.getInResponseTo());
		if (oldSession != null && !oldSession.getId().equals(session.getId())) {
			log.info("Copying session attributes from orphaned session (" + oldSession.getId() + ") to new session (" + session.getId() + ")");

			// copy attributes stored on the old session to the new session
			@SuppressWarnings("unchecked")
			Enumeration<String> enumeration = oldSession.getAttributeNames();
			while (enumeration.hasMoreElements()) {
				String name = enumeration.nextElement();

				session.setAttribute(name, oldSession.getAttribute(name));
			}
		}
		
		if (allowPassive && response.isPassive()) {
			log.debug("Received passive response, setting passive userassertion");
			Assertion assertion = SAMLUtil.buildXMLObject(Assertion.class);
			assertion.setID("" + System.currentTimeMillis());
			ctx.getSessionHandler().setAssertion(session.getId(), new OIOAssertion(assertion));
			PassiveUserAssertion passiveUserAssertion = new PassiveUserAssertion(ctx.getConfiguration().getString(Constants.PROP_PASSIVE_USER_ID));
			session.setAttribute(Constants.SESSION_USER_ASSERTION, passiveUserAssertion);

			Audit.log(Operation.LOGIN, passiveUserAssertion.getSubject());
		}
		else {
			OIOAssertion assertion = response.getAssertion();

			assertion.validateAssertion(validator, ctx.getSpMetadata().getEntityID(), ctx.getSpMetadata().getAssertionConsumerServiceLocation(0));

			UserAssertion userAssertion = new UserAssertionImpl(assertion);
			if (!invokeAuthenticationHandler(ctx, userAssertion)) {
				Audit.logError(Operation.LOGIN, false, response.getInResponseTo(), "Authentication handler stopped authentication");
				log.error("Authentication handler stopped authentication");
				return;
			}
			Audit.setAssertionId(assertion.getID());
			Audit.log(Operation.LOGIN, assertion.getSubjectNameIDValue() + "/" + assertion.getAssuranceLevel() + " via " + assertion.getIssuer());
			Audit.log(Operation.LOGIN_SESSION, Integer.toString(session.getMaxInactiveInterval()));

			// Store the assertion in the session store

			// release the DOM tree now the signature is validated - due to large memory consumption
			Assertion assertion2 = assertion.getAssertion();
			assertion2.releaseChildrenDOM(true);
			assertion2.releaseDOM();
			assertion2.detach();

			ctx.getSessionHandler().setAssertion(session.getId(), assertion);
			session.setAttribute(Constants.SESSION_USER_ASSERTION, userAssertion);
		}

		if (relayState.getRelayState() != null) {
			HTTPUtils.sendResponse(ctx.getSessionHandler().getRequest(relayState.getRelayState()), ctx);
		}
		else {
			HTTPUtils.sendResponse(null, ctx);
		}
	}

	private static boolean invokeAuthenticationHandler(RequestContext ctx, UserAssertion userAssertion) {
		String handlerClass = ctx.getConfiguration().getString(Constants.PROP_AUTHENTICATION_HANDLER, null);
		if (handlerClass != null) {
			log.debug("Authentication handler: " + handlerClass);

			AuthenticationHandler handler = (AuthenticationHandler) Utils.newInstance(ctx.getConfiguration(), Constants.PROP_AUTHENTICATION_HANDLER);
			return handler.userAuthenticated(userAssertion, ctx.getRequest(), ctx.getResponse());
		}

		log.debug("No authentication handler configured");
		return true;
	}
}
