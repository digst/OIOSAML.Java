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
 * created by Trifork A/S are Copyright (C) 2009 Danish National IT 
 * and Telecom Agency (http://www.itst.dk). All Rights Reserved.
 * 
 * Contributor(s):
 *   Joakim Recht <jre@trifork.com>
 *   Rolf Njor Jensen <rolf@trifork.com>
 *
 */
package dk.itst.oiosaml.sp.develmode;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import dk.itst.oiosaml.logging.Logger;
import dk.itst.oiosaml.logging.LoggerFactory;
import org.apache.commons.configuration.Configuration;
import org.apache.velocity.VelocityContext;
import org.joda.time.DateTime;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.sp.UserAssertion;
import dk.itst.oiosaml.sp.UserAssertionHolder;
import dk.itst.oiosaml.sp.UserAssertionImpl;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.service.SAMLHttpServletRequest;
import dk.itst.oiosaml.sp.service.util.Constants;
import dk.itst.oiosaml.sp.service.util.HTTPUtils;
import dk.itst.oiosaml.sp.util.AttributeUtil;

public class DevelModeImpl implements DevelMode {
	private static final Logger log = LoggerFactory.getLogger(DevelModeImpl.class);

	@SuppressWarnings("unchecked")
	public void doFilter(HttpServletRequest req, HttpServletResponse res, FilterChain fc, Configuration conf) throws IOException, ServletException {

		// Inserted to avoid loginpage when a samlhandler is requested in develmode
		if (req.getServletPath().equals(conf.getProperty(Constants.PROP_SAML_SERVLET))) {
			log.debug("Develmode: Request to SAML servlet, access granted");
			fc.doFilter(req, res);
			return;
		}

		UserAssertionHolder.set(null);
		UserAssertion ua = (UserAssertion) req.getSession().getAttribute(Constants.SESSION_USER_ASSERTION);
		if (ua == null) {
			String[] users = conf.getStringArray("oiosaml-sp.develmode.users");
			if (users == null || users.length == 0) {
				log.error("No users defined in properties. Set oiosaml-sp.develmode.users");
				res.setStatus(500);
				HTTPUtils.sendCacheHeaders(res);
				render("nousers.vm", res, new HashMap<String, Object>());
				return;
			}

			if (users.length == 1) {
				ua = selectUser(users[0], conf);
			}
			else {
				String selected = req.getParameter("__oiosaml_devel");
				if (selected == null || !Arrays.asList(users).contains(selected)) {
					HTTPUtils.sendCacheHeaders(res);

					Map<String, Object> params = new HashMap<String, Object>();
					params.put("users", users);
					params.put("params", buildParameterString(req.getParameterMap()));
					render("users.vm", res, params);
					return;
				}

				HTTPUtils.sendCacheHeaders(res);
				ua = selectUser(selected, conf);
				req.getSession().setAttribute(Constants.SESSION_USER_ASSERTION, ua);
				res.sendRedirect(req.getRequestURI() + "?" + buildParameterString(req.getParameterMap()));
				return;
			}
		}

		if (ua != null) {
			req.getSession().setAttribute(Constants.SESSION_USER_ASSERTION, ua);
			UserAssertionHolder.set(ua);

			HttpServletRequestWrapper requestWrap = new SAMLHttpServletRequest(req, ua, "");
			fc.doFilter(requestWrap, res);
			return;
		}

		log.error("No assertion found");
		res.sendError(500);
	}

	private static String buildParameterString(Map<String, String[]> params) {
		StringBuilder sb = new StringBuilder();
		String sep = "";
		try {
			for (Map.Entry<String, String[]> e : params.entrySet()) {
				if ("__oiosaml_devel".equals(e.getKey()))
					continue;
				for (String val : e.getValue()) {
					sb.append(sep);
					sep = "&";
					sb.append(e.getKey()).append("=").append(URLEncoder.encode(val, "UTF-8"));
				}
			}
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
		return sb.toString();
	}

	private static UserAssertion selectUser(String user, Configuration conf) {
		Map<String, String[]> attributes = getAttributes(user, conf);

		Assertion a = SAMLUtil.buildXMLObject(Assertion.class);
		a.setSubject(SAMLUtil.createSubject(user, "urn:test", new DateTime().plusHours(1)));

		AttributeStatement as = SAMLUtil.buildXMLObject(AttributeStatement.class);
		a.getAttributeStatements().add(as);

		for (Map.Entry<String, String[]> e : attributes.entrySet()) {
			Attribute attr = AttributeUtil.createAttribute(e.getKey(), e.getKey(), "");
			for (String val : e.getValue()) {
				attr.getAttributeValues().add(AttributeUtil.createAttributeValue(val));
			}
			as.getAttributes().add(attr);
		}
		
		return new UserAssertionImpl(new OIOAssertion(a));
	}

	private static Map<String, String[]> getAttributes(String user, Configuration conf) {
		String prefix = "oiosaml-sp.develmode." + user + ".";

		Map<String, String[]> attributes = new HashMap<String, String[]>();
		Iterator<?> i = conf.getKeys();
		while (i.hasNext()) {
			String key = (String) i.next();
			if (key.startsWith(prefix)) {
				String attr = key.substring(prefix.length());
				String[] value = conf.getStringArray(key);
				attributes.put(attr, value);
			}
		}
		return attributes;
	}

	private static void render(String template, HttpServletResponse response, Map<String, ?> params) {
		VelocityContext ctx = new VelocityContext();
		for (Map.Entry<String, ?> e : params.entrySet()) {
			ctx.put(e.getKey(), e.getValue());
		}

		try {
			HTTPUtils.getEngine().mergeTemplate(template, "UTF-8", ctx, response.getWriter());
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}

	}
}
