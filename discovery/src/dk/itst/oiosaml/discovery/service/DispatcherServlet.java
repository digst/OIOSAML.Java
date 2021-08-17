package dk.itst.oiosaml.discovery.service;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class DispatcherServlet extends HttpServlet {

	

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String path = req.getPathInfo();
		if (path == null) {
			defaultDispatch(req, resp);
		} else {
			RequestDispatcher dispatcher = getServletContext().getNamedDispatcher(path.substring(1));
			if (dispatcher == null) {
				defaultDispatch(req, resp);
			} else {
				dispatcher.forward(req, resp);
			}
		}
	}
	
	private void defaultDispatch(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		getServletContext().getNamedDispatcher("discovery").forward(req, resp);
	}
	
	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		doGet(req, resp);
	}
}
