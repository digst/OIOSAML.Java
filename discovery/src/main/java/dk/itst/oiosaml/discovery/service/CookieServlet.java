package dk.itst.oiosaml.discovery.service;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CookieServlet extends AbstractServlet {

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String val = req.getParameter(SAML_IDP_COOKIE);
		if (val == null) {
			req.getRequestDispatcher("/cookie.html").forward(req, resp);
			return;
		} else {
			Cookie c = new Cookie(SAML_IDP_COOKIE, val);
			resp.addCookie(c);
			String redir = req.getParameter(REFERER_PARAMETER);
			if (redir != null) {
				sendRedirect(redir, val, resp);
			} else {
				resp.getWriter().println("Cookie set to " + val);
			}
		}
	}
	
	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		doGet(req, resp);
	}
}
