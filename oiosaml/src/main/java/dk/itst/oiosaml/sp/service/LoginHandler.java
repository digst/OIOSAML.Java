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
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import dk.itst.oiosaml.logging.Logger;
import dk.itst.oiosaml.logging.LoggerFactory;
import org.apache.commons.configuration.Configuration;
import org.apache.velocity.VelocityContext;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.xml.util.Base64;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.configuration.SAMLConfigurationFactory;
import dk.itst.oiosaml.logging.Audit;
import dk.itst.oiosaml.logging.Operation;
import dk.itst.oiosaml.sp.UserAssertion;
import dk.itst.oiosaml.sp.UserAssertionHolder;
import dk.itst.oiosaml.sp.bindings.BindingHandler;
import dk.itst.oiosaml.sp.metadata.IdpMetadata;
import dk.itst.oiosaml.sp.metadata.IdpMetadata.Metadata;
import dk.itst.oiosaml.sp.model.OIOAuthnRequest;
import dk.itst.oiosaml.sp.service.session.SessionCopyListener;
import dk.itst.oiosaml.sp.service.util.Constants;
import dk.itst.oiosaml.sp.service.util.HTTPUtils;

public class LoginHandler implements SAMLHandler {
	private static final Logger log = LoggerFactory.getLogger(LoginHandler.class);

	public void handleGet(RequestContext context) throws ServletException, IOException {
		if (log.isDebugEnabled()) log.debug("Go to login...");
		
		IdpMetadata idpMetadata = context.getIdpMetadata();
		Configuration conf = context.getConfiguration();
		HttpServletRequest request = context.getRequest();
		HttpServletResponse response = context.getResponse();
		
		Metadata metadata;
		if (idpMetadata.enableDiscovery()) {
			log.debug("Discovery profile is active");
			String samlIdp = request.getParameter(Constants.DISCOVERY_ATTRIBUTE);
			if (samlIdp == null) {
				String discoveryLocation = conf.getString(Constants.DISCOVERY_LOCATION);
				log.debug("No _saml_idp discovery value found, redirecting to discovery service at " + discoveryLocation);
				String url = request.getRequestURL().toString();
				if (request.getQueryString() != null) {
					url += "?" + request.getQueryString();
				}
				Audit.log(Operation.DISCOVER, true, "", discoveryLocation);
				HTTPUtils.sendMetaRedirect(response, discoveryLocation, "r=" + URLEncoder.encode(url, "UTF-8"), true);
				return;
			} else if ("".equals(samlIdp)) {
				String defaultIdP = conf.getString(Constants.PROP_DISCOVERY_DEFAULT_IDP, null);
				if (defaultIdP != null) {
					log.debug("No IdP discovered, using default IdP from configuration: " + defaultIdP);
					metadata = idpMetadata.getMetadata(defaultIdP);
				} else {
					if (conf.getBoolean(Constants.PROP_DISCOVERY_PROMPT, false)) {
						String url = request.getRequestURL().toString();
						String relayState = request.getParameter(Constants.SAML_RELAYSTATE);
						if (relayState != null) {
						    url += "?RelayState=" + relayState;
						} 
						promptIdp(context, url);
						return;
					}
					
					log.debug("No IdP discovered, using first from metadata");
					metadata = idpMetadata.getFirstMetadata();
				}
			} else {
				String[] entityIds = SAMLUtil.decodeDiscoveryValue(samlIdp);
				Audit.log(Operation.DISCOVER, false, "", Arrays.asList(entityIds).toString());
				metadata = idpMetadata.findSupportedEntity(entityIds);
				if (metadata != null) {
					log.debug("Discovered idp " + metadata.getEntityID());
				} else {
					log.debug("No supported IdP discovered, using first from metadata");
					metadata = idpMetadata.getFirstMetadata();
				}
			}
		} else {
			metadata = idpMetadata.getFirstMetadata();
		}
		Audit.log(Operation.DISCOVER, metadata.getEntityID());
		
		Endpoint signonLocation = metadata.findLoginEndpoint(conf.getStringArray(Constants.PROP_SUPPORTED_BINDINGS));
		if (signonLocation == null) {
			String msg = "Could not find a valid IdP signon location. Supported bindings: " + conf.getString(Constants.PROP_SUPPORTED_BINDINGS) + ", available: " + metadata.getSingleSignonServices();
			log.error(msg);
			throw new RuntimeException(msg);
		}
		log.debug("Signing on at " + signonLocation.getLocation());
		
		BindingHandler bindingHandler = context.getBindingHandlerFactory().getBindingHandler(signonLocation.getBinding());
		log.info("Using idp " + metadata.getEntityID() + " at " + signonLocation.getLocation() + " with binding " + signonLocation.getBinding());

		HttpSession session = context.getSession();
		UserAssertion ua = (UserAssertion) session.getAttribute(Constants.SESSION_USER_ASSERTION);
		session.removeAttribute(Constants.SESSION_USER_ASSERTION);
		UserAssertionHolder.set(null);

		String relayState = context.getRequest().getParameter(Constants.SAML_RELAYSTATE);
		OIOAuthnRequest authnRequest = OIOAuthnRequest.buildAuthnRequest(signonLocation.getLocation(), context.getSpMetadata().getEntityID(), context.getSpMetadata().getDefaultAssertionConsumerService().getBinding(), context.getSessionHandler(), relayState, context.getSpMetadata().getDefaultAssertionConsumerService().getLocation());
		authnRequest.setNameIDPolicy(conf.getString(Constants.PROP_NAMEID_POLICY, null), conf.getBoolean(Constants.PROP_NAMEID_POLICY_ALLOW_CREATE, false));
		authnRequest.setForceAuthn(isForceAuthnEnabled(request, conf));

		if (ua == null) {
			authnRequest.setPasive(conf.getBoolean(Constants.PROP_PASSIVE, false));
		}
		Audit.log(Operation.AUTHNREQUEST_SEND, true, authnRequest.getID(), authnRequest.toXML());

		context.getSessionHandler().registerRequest(authnRequest.getID(), metadata.getEntityID());
		
		// link outgoing request to existing session (SameSite=Lax support)
		SAMLConfigurationFactory.getConfiguration().getSameSiteSessionSynchronizer().linkSession(authnRequest.getID(), session.getId());
		
		bindingHandler.handle(request, response, context.getCredential(), authnRequest);
	}

	public void handlePost(RequestContext context) throws ServletException, IOException {
		handleGet(context);
	}

	private static boolean isForceAuthnEnabled(HttpServletRequest servletRequest, Configuration conf) {
		String[] urls = conf.getStringArray(Constants.PROP_FORCE_AUTHN_URLS);
		if (urls == null) return false;
		
		String path = servletRequest.getPathInfo();
		if (path == null) {
			path = "/";
		}
		if (log.isDebugEnabled()) log.debug("ForceAuthn urls: " + Arrays.toString(urls) + "; path: " + path);
		
		
		for (String url : urls) {
			if (path.matches(url.trim())) {
				if (log.isDebugEnabled()) log.debug("Requested url " + path + " is in forceauthn list " + Arrays.toString(urls));
				return true;
			}
		}

        // Force authentication can also be specified through the query string.
        if(servletRequest.getParameterMap().containsKey(Constants.QUERY_STRING_FORCE_AUTHN)){
            String value = servletRequest.getParameter(Constants.QUERY_STRING_FORCE_AUTHN);
            return value.toLowerCase().equals("true");
        }

		return false;
	}
	
	private static void promptIdp(RequestContext context, String returnUrl) throws ServletException, IOException {
		log.debug("Prompting user for IdP");
		
		Map<String, String> idps = new HashMap<String, String>();
		for (String id : context.getIdpMetadata().getEntityIDs()) {
			StringBuilder url = new StringBuilder(returnUrl);
			if (returnUrl.indexOf('?') > -1) {
				url.append("&");
			} else {
				url.append("?");
			}
			url.append(Constants.DISCOVERY_ATTRIBUTE).append("=");
			url.append(Base64.encodeBytes(id.getBytes(), Base64.DONT_BREAK_LINES));
			idps.put(id, url.toString());
		}

		String servlet = context.getConfiguration().getString(Constants.PROP_DISCOVERY_PROMPT_SERVLET, null);
		if (servlet != null) {
			HttpServletRequest request = context.getRequest();
			request.setAttribute("entityIds", idps);
			request.getRequestDispatcher(servlet).forward(request, context.getResponse());
		} else {
			VelocityContext vc = new VelocityContext();
			vc.put("entityIds", idps);
			
			try {
				HTTPUtils.getEngine().mergeTemplate("idp.vm", "UTF-8", vc, context.getResponse().getWriter());
			} catch (Exception e) {
				log.error("Unable to render IdP list", e);
				throw new ServletException(e);
			}
		}
		
	}

}
