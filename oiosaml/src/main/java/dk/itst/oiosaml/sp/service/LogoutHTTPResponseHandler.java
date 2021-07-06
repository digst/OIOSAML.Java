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
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import dk.itst.oiosaml.configuration.SAMLConfigurationFactory;
import dk.itst.oiosaml.logging.Audit;
import dk.itst.oiosaml.logging.Logger;
import dk.itst.oiosaml.logging.LoggerFactory;
import dk.itst.oiosaml.logging.Operation;
import dk.itst.oiosaml.sp.metadata.IdpMetadata.Metadata;
import dk.itst.oiosaml.sp.model.OIOLogoutResponse;
import dk.itst.oiosaml.sp.service.session.SessionCopyListener;
import dk.itst.oiosaml.sp.service.util.Constants;

/**
 * Servlet used to end a SLO - i.e. receiving the &lt;LogoutResponse&gt; from the
 * Login Site.
 * 
 */
public class LogoutHTTPResponseHandler implements SAMLHandler{

	@SuppressWarnings("unused")
	private static final long serialVersionUID = 2487601130738744767L;
	private static final Logger log = LoggerFactory.getLogger(LogoutHTTPResponseHandler.class);
	public static final String VERSION = "$Id: LogoutHTTPResponseHandler.java 2950 2008-05-28 08:22:34Z jre $";
	
	/**
	 * Receive a &lt;LogoutResponse&gt;
	 */
	public void handleGet(RequestContext ctx) throws ServletException, IOException {
		HttpServletRequest request = ctx.getRequest();
		HttpSession session = ctx.getSession();
		if (log.isDebugEnabled()) {
			log.debug("Calling URL.:" + request.getRequestURI()
					+ "?" + request.getQueryString());

			log.debug("samlResponse...:" + request.getParameter(Constants.SAML_SAMLRESPONSE));
			log.debug("relayState....:" + request.getParameter(Constants.SAML_RELAYSTATE));
			log.debug("sigAlg........:" + request.getParameter(Constants.SAML_SIGALG));
			log.debug("signature.....:" + request.getParameter(Constants.SAML_SIGNATURE));
		}

		OIOLogoutResponse logoutResponse = OIOLogoutResponse.fromHttpRedirect(request);

		Audit.log(Operation.LOGOUTREQUEST, false, logoutResponse.getInResponseTo(), logoutResponse.toXML());

		String idpEntityId = ctx.getSessionHandler().removeEntityIdForRequest(logoutResponse.getInResponseTo());
		Metadata metadata = ctx.getIdpMetadata().getMetadata(idpEntityId);
		logoutResponse.validate(null, ctx.getSpMetadata().getSingleLogoutServiceHTTPRedirectResponseLocation(), request.getParameter(Constants.SAML_SIGNATURE), request.getQueryString(), metadata.getPublicKeys());

		ctx.getSessionHandler().logOut(session);
		
		Audit.log(Operation.LOGOUT, null);

		String homeUrl = ctx.getConfiguration().getString(Constants.PROP_HOME);
		if (log.isDebugEnabled()) {
			log.debug("sendRedirect to..:" + homeUrl);
		}
		if (homeUrl == null) homeUrl = request.getContextPath();

		// Go to the default page after logout
		ctx.getResponse().sendRedirect(homeUrl);
	}

	public void handlePost(RequestContext ctx) throws ServletException, IOException {
		HttpServletRequest request = ctx.getRequest();

		if (log.isDebugEnabled()) {
			log.debug("samlResponse...:" + request.getParameter(Constants.SAML_SAMLRESPONSE));
		}

		OIOLogoutResponse logoutResponse = OIOLogoutResponse.fromPostRequest(request);

		Audit.log(Operation.LOGOUTREQUEST, false, logoutResponse.getInResponseTo(), logoutResponse.toXML());

		String idpEntityId = ctx.getSessionHandler().removeEntityIdForRequest(logoutResponse.getInResponseTo());
		Metadata metadata = ctx.getIdpMetadata().getMetadata(idpEntityId);

		logoutResponse.validate(null, ctx.getSpMetadata().getSingleLogoutServiceHTTPPostResponseLocation(), metadata.getPublicKeys());

		// fetch the session from stored session in the outgoing request
		// - if this fails, use the current HttpSession
		// - note that we do not default to the current HttpSession in the POST case, as
		//   a SameSite=Lax setting on the session cookie will result in a new session being
		//   created on a cross-domain POST		
		HttpSession session = SAMLConfigurationFactory.getConfiguration().getSameSiteSessionSynchronizer().getSession(logoutResponse.getInResponseTo());
		if (session == null) {
			session = ctx.getSession();
		}

		ctx.getSessionHandler().logOut(session);
		
		Audit.log(Operation.LOGOUT, null);

		String homeUrl = ctx.getConfiguration().getString(Constants.PROP_HOME);
		if (log.isDebugEnabled()) {
			log.debug("sendRedirect to..:" + homeUrl);
		}
		if (homeUrl == null) homeUrl = request.getContextPath();
		
		// Go to the default page after logout
		ctx.getResponse().sendRedirect(homeUrl);
	}
}
