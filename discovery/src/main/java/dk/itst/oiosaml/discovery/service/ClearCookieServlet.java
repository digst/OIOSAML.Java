package dk.itst.oiosaml.discovery.service;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ClearCookieServlet extends AbstractServlet {

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		Cookie cookie = findCookie(req.getCookies());
		if (cookie != null) {
			cookie.setMaxAge(0);
			resp.addCookie(cookie);
		}

		resp.getWriter().println("Cookie cleared");
	}
}
