package dk.itst.oiosaml.discovery.service;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletResponse;

public class AbstractServlet extends HttpServlet {
	public static final String REFERER_PARAMETER = "r";
	public static final String SAML_IDP_COOKIE = "_saml_idp";
	

	protected void sendRedirect(String url, String cookie, HttpServletResponse res) throws IOException {
		res.setContentType("text/html");
		
		PrintWriter w = res.getWriter();
		w.write("<html><head>");
		w.write("<meta http-equiv=\"refresh\" content=\"0;url=");
		w.write(url);
		if (url.indexOf('?') > -1) {
			w.write("&_saml_idp=");
		} else {
			w.write("?_saml_idp=");
		}
		w.write(cookie);
		w.write("\">");
		w.write("</head><body></body></html>");
	}
	
	protected Cookie findCookie(Cookie[] cookies) {
		if (cookies == null) return null;
		
		for (Cookie cookie : cookies) {
			if (SAML_IDP_COOKIE.equalsIgnoreCase(cookie.getName())) {
				return cookie;
			}
		}
		return null;
	}

}
