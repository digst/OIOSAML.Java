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
package dk.itst.oiosaml.sp.service.util;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import dk.itst.oiosaml.logging.Logger;
import dk.itst.oiosaml.logging.LoggerFactory;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;

import dk.itst.oiosaml.sp.service.RequestContext;
import dk.itst.oiosaml.sp.service.session.Request;

/**
 * Utility class for handling HTTP requests and responses.
 * 
 * @author Joakim Recht <jre@trifork.com>
 *
 */
public class HTTPUtils {
	private static final Logger log = LoggerFactory.getLogger(HTTPUtils.class);
	
	private HTTPUtils() {}

	
	/**
	 * Send a redirect using a meta tag.
	 * 
	 * @param res Http response object.
	 * @param url URL to redirect to.
	 * @throws IOException
	 */
	public static void sendMetaRedirect(HttpServletResponse res, String url, String query, boolean saveFragment) throws IOException {
		res.setContentType("text/html");
		sendCacheHeaders(res);

		PrintWriter w = res.getWriter();
		w.write("<html><head>");
		w.write("<meta http-equiv=\"refresh\" content=\"0;url=");
		w.write(url);
		if (query != null) {
			if (url.contains("?")) {
				w.write("&");
			} else {
				w.write("?");
			}
			w.write(query);
		}
		w.write("\">");
		w.write("</head><body>");
		if (saveFragment) {
			w.write("<script type=\"text/javascript\">document.cookie = 'oiosaml-fragment=' + escape(location.hash) + '; path=/';</script>");
		}
		w.write("</body></html>");
	}


	public static void sendCacheHeaders(HttpServletResponse res) {
		res.addHeader("Pragma", "no-cache");
		res.addDateHeader("Expires", -1);
		res.addHeader("Cache-Control", "no-cache");
		res.addHeader("Cache-Control", "no-store");
	}
	
	public static String getFragmentCookie(HttpServletRequest req) {
		Cookie[] cookies = req.getCookies();
		if (cookies == null) return null;
		
		for (Cookie cookie : cookies) {
			if ("oiosaml-fragment".equals(cookie.getName())) {
				return cookie.getValue();
			}
		}
		return null;
	}
	
	public static void removeFragmentCookie(HttpServletResponse res) {
		Cookie c = new Cookie("oiosaml-fragment", "");
		c.setPath("/");
		c.setMaxAge(0);
		res.addCookie(c);
	}
	
	/**
	 * Replay a request.
	 * 
	 * <p>This method will take information about a request and replay it - either by issuing a redirect if the request was a GET request, or by 
	 * creating a POST form with the original form data.</p>
	 * 
	 * <p>In the POST case, the context configuration is checked for the {@link Constants#PROP_REPOST_SERVLET} property. If it has been set,
	 * this servlet will be invoked. Otherwise a default page is displayed.</p>
	 * 
	 * <p>In both cases, two attributes are added to the request context: "request" which holds the {@link Request} object and "home" which
	 * contains a link to the default hom page.</p>
	 * 
	 */
	public static void sendResponse(Request req, RequestContext ctx) throws IOException, ServletException {
		sendCacheHeaders(ctx.getResponse());
		
		String home = ctx.getConfiguration().getString(Constants.PROP_HOME);
		if (req == null) {
			log.debug("No request saved in RelayState, redrecting to default url: " + home);
			ctx.getResponse().sendRedirect(home);
			return;
		}
		
		String uri = req.getRequestURI();
		if ("GET".equals(req.getMethod())) {
			uri = uri.replaceAll("/[/]*", "/");
			StringBuilder sb = new StringBuilder(uri);
			if (req.getQueryString() != null) {
				sb.append("?");
				sb.append(req.getQueryString());
			}
			String fragmentCookie = getFragmentCookie(ctx.getRequest());
			if (fragmentCookie != null) {
				removeFragmentCookie(ctx.getResponse());
				sb.append(URLDecoder.decode(fragmentCookie, "utf-8"));
			}
			
			if (log.isDebugEnabled()) log.debug("Saved GET request, redirecting to " + sb);
			ctx.getResponse().sendRedirect(sb.toString());
		} else {
			Map<String, String[]> params = new HashMap<String, String[]>();
			for (Map.Entry<String, String[]> e : req.getParameters().entrySet()) {
				ArrayList<String> values = new ArrayList<String>();
				
				for (String val : e.getValue()) {
					values.add(Utils.htmlEntityEncode(val));
				}
				params.put(Utils.htmlEntityEncode(e.getKey()), values.toArray(new String[0]));
			}
			req = new Request(uri, req.getQueryString(), req.getMethod(), params);
			
			String postServlet = ctx.getConfiguration().getString(Constants.PROP_REPOST_SERVLET, null);
			if (postServlet != null) {
				if (log.isDebugEnabled()) log.debug("POST Request with custom servlet at " + postServlet + " for action " + uri);
				ctx.getRequest().setAttribute("request", req);
				ctx.getRequest().setAttribute("home", home);
				ctx.getRequest().getRequestDispatcher(postServlet).forward(ctx.getRequest(), ctx.getResponse());
			} else {
				if (log.isDebugEnabled()) log.debug("Saved POST request with default servlet for action " + uri);
				
				VelocityContext vc = new VelocityContext();
				vc.put("request", req);
				vc.put("home", home);
				
				ctx.getResponse().setContentType("text/html");

				try {
					getEngine().mergeTemplate("repost.vm", "UTF-8", vc, ctx.getResponse().getWriter());
				} catch (Exception e1) {
					log.error("Unable to render error template", e1);
					throw new ServletException(e1);
				}
			}
		}
			
		
	}
	
	public static VelocityEngine getEngine() {
		VelocityEngine engine = new VelocityEngine();
		engine.setProperty(VelocityEngine.RESOURCE_LOADER, "classpath");
		engine.setProperty("classpath.resource.loader.class", "org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");
		try {
			engine.init();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
		return engine;

	}
}
