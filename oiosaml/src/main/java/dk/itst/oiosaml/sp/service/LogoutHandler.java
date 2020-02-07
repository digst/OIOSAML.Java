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

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;

import dk.itst.oiosaml.configuration.SAMLConfigurationFactory;
import dk.itst.oiosaml.logging.Audit;
import dk.itst.oiosaml.logging.Logger;
import dk.itst.oiosaml.logging.LoggerFactory;
import dk.itst.oiosaml.logging.Operation;
import dk.itst.oiosaml.sp.AuthenticationHandler;
import dk.itst.oiosaml.sp.LogoutAuthenticationHandler;
import dk.itst.oiosaml.sp.metadata.IdpMetadata.Metadata;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.model.OIOLogoutRequest;
import dk.itst.oiosaml.sp.service.util.Constants;
import dk.itst.oiosaml.sp.service.util.Utils;

public class LogoutHandler implements SAMLHandler{

	@SuppressWarnings("unused")
	private static final long serialVersionUID = 3843822219113371749L;
	public static final String VERSION = "$Id: LogoutHandler.java 2950 2008-05-28 08:22:34Z jre $";
	private static final Logger log = LoggerFactory.getLogger(LogoutHandler.class);
		
	/**
	 * Send a &lt;LogoutRequest&gt; to the Login Site and start a SLO.
	 */
	public void handleGet(RequestContext context) throws ServletException, IOException {
		HttpSession session = context.getSession();

		// Check that user is logged in...
		if (!context.getSessionHandler().isLoggedIn(session.getId())) {
			context.getSessionHandler().logOut(session);
			String homeUrl = context.getConfiguration().getString(Constants.PROP_HOME, context.getRequest().getContextPath());
			context.getResponse().sendRedirect(homeUrl);
			return;
		}
		
		OIOAssertion assertion = context.getSessionHandler().getAssertion(session.getId());
		String entityID = assertion.getAssertion().getIssuer().getValue();
		Metadata metadata = context.getIdpMetadata().getMetadata(entityID);

		OIOLogoutRequest lr = OIOLogoutRequest.buildLogoutRequest(session, metadata.getSingleLogoutServiceLocation(), context.getSpMetadata().getEntityID(), context.getSessionHandler());
		String redirectURL = lr.getRedirectRequestURL(context.getCredential());
		
		Audit.log(Operation.LOGOUTREQUEST, true, lr.getID(), lr.toXML());

		context.getSessionHandler().registerRequest(lr.getID(), metadata.getEntityID());
		context.getSessionHandler().logOut(session);
		
		invokeAuthenticationHandler(context);

		if (log.isDebugEnabled()) log.debug("Redirect to..:" + redirectURL);
		Audit.log(Operation.LOGOUT, assertion.getSubjectNameIDValue());

		// link outgoing request to existing session (SameSite=Lax support)
		SAMLConfigurationFactory.getConfiguration().getSameSiteSessionSynchronizer().linkSession(lr.getID(), session.getId());

		context.getResponse().sendRedirect(redirectURL);
	}

	public void handlePost(RequestContext context) throws ServletException, IOException {
		throw new UnsupportedOperationException();
	}

	private static void invokeAuthenticationHandler(RequestContext ctx) {
		String handlerClass = ctx.getConfiguration().getString(Constants.PROP_AUTHENTICATION_HANDLER, null);
		if (handlerClass != null) {
			log.debug("Authentication handler: " + handlerClass);
			
			AuthenticationHandler handler = (AuthenticationHandler) Utils.newInstance(ctx.getConfiguration(), Constants.PROP_AUTHENTICATION_HANDLER);
			if (handler instanceof LogoutAuthenticationHandler) {
				((LogoutAuthenticationHandler)handler).userLoggedOut(ctx.getRequest(), ctx.getResponse());
			}
		} else {
			log.debug("No authentication handler configured");
		}
	}

}
