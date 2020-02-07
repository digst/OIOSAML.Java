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
 *   Aage Nielsen <ani@openminds.dk>
 *
 */
package dk.itst.oiosaml.sp.service;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import dk.itst.oiosaml.logging.Logger;
import dk.itst.oiosaml.logging.LoggerFactory;
import org.apache.commons.configuration.Configuration;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.xml.security.credential.Credential;

import dk.itst.oiosaml.configuration.OIOSAMLBootstrap;
import dk.itst.oiosaml.configuration.SAMLConfigurationFactory;
import dk.itst.oiosaml.error.WrappedException;
import dk.itst.oiosaml.logging.Audit;
import dk.itst.oiosaml.security.CredentialRepository;
import dk.itst.oiosaml.sp.bindings.BindingHandlerFactory;
import dk.itst.oiosaml.sp.bindings.DefaultBindingHandlerFactory;
import dk.itst.oiosaml.sp.configuration.ConfigurationHandler;
import dk.itst.oiosaml.sp.metadata.IdpMetadata;
import dk.itst.oiosaml.sp.metadata.SPMetadata;
import dk.itst.oiosaml.sp.service.session.SessionHandler;
import dk.itst.oiosaml.sp.service.session.SessionHandlerFactory;
import dk.itst.oiosaml.sp.service.util.Constants;
import dk.itst.oiosaml.sp.service.util.Utils;

/**
 * Main servlet for all SAML handling.
 * 
 * This servlet simply dispatches to
 * {@link dk.itst.oiosaml.sp.model.OIOSamlObject}s based on the requested url.
 * 
 * @author Joakim Recht <jre@trifork.com>
 * @author Rolf Njor Jensen <rolf@trifork.com>
 * @author Aage Nielsen <ani@openminds.dk>
 * 
 */
public class DispatcherServlet extends HttpServlet {
	private static final long serialVersionUID = 45789427728055436L;
	private static final Logger log = LoggerFactory.getLogger(DispatcherServlet.class);

	private transient IdpMetadata idpMetadata;
	private transient SPMetadata spMetadata;
	private Configuration configuration;
	private Credential credential;

	private final Map<String, SAMLHandler> handlers = new HashMap<String, SAMLHandler>();
	private boolean initialized = false;
	private transient VelocityEngine engine;

	private BindingHandlerFactory bindingHandlerFactory;

	private SessionHandlerFactory sessionHandlerFactory;
	private ServletContext servletContext;

	/**
	 * Static initializer for bootstrapping OpenSAML.
	 * 
	 * ... we need this in both SPFilter and DispatcherServlet as the order of creation of these two depends on the servlet container
	 */
	static {
		OIOSAMLBootstrap.init();
	}

	@Override
	public final void init(ServletConfig config) throws ServletException {
		setHandler(new ConfigurationHandler(), "configure");

		servletContext = config.getServletContext();

		try {
			initServlet();
		} catch (Exception e) {
			e.printStackTrace();
		}

		engine = new VelocityEngine();
		engine.setProperty(VelocityEngine.RESOURCE_LOADER, "classpath");
		engine.setProperty("classpath.resource.loader.class",
				"org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");
		try {
			engine.init();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private void initServlet() throws WrappedException, NoSuchAlgorithmException, CertificateException,
			KeyStoreException, IOException {
		try {
			if (initialized == false) {
				setConfiguration(SAMLConfigurationFactory.getConfiguration().getSystemConfiguration());

				handlers.putAll(Utils.getHandlers(configuration, servletContext));
				if (log.isDebugEnabled())
					log.debug("Found handlers: " + handlers);

				setHandler(new IndexHandler(), "");
				sessionHandlerFactory = SessionHandlerFactory.Factory.newInstance(configuration);
				sessionHandlerFactory.getHandler().resetReplayProtection(
						configuration.getInt(Constants.PROP_NUM_TRACKED_ASSERTIONIDS));

				if (configuration.getBoolean(Constants.PROP_DEVEL_MODE, false)) {
					log.warn("Running in devel mode");
					return;
				}
				setBindingHandler(new DefaultBindingHandlerFactory());
				setIdPMetadata(IdpMetadata.getInstance());
				setSPMetadata(SPMetadata.getInstance());
				setCredential(new CredentialRepository().getCredential(SAMLConfigurationFactory.getConfiguration()
						.getKeystore(), configuration.getString(Constants.PROP_CERTIFICATE_PASSWORD)));

				initialized = true;
			}
		} catch (IllegalStateException e) {
			try {
				handlers.putAll(Utils.getHandlers(SAMLConfigurationFactory.getConfiguration().getCommonConfiguration(),
						servletContext));
			} catch (IOException e1) {
				log.error("Unable to load config", e);
			}
		}
	}

	@Override
	protected final void doPut(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
		doPost(req, res);
	}

	@Override
	protected final void doDelete(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
		doGet(req, res);
	}

	@Override
	protected final void doGet(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
		// TODO: Find a strategy for catching configuration errors.
		try {
			initServlet();
		} catch (Exception e) {
			e.printStackTrace();
		}

		String action = req.getRequestURI().substring(req.getRequestURI().lastIndexOf("/") + 1);
		Audit.init(req);

		// This is needed if DispatcherServlet isn't protected
		// by the SPFilter
		if (handlers.containsKey(action)) {
			try {
				SAMLHandler handler = handlers.get(action);
				SessionHandler sessionHandler = sessionHandlerFactory != null ? sessionHandlerFactory.getHandler()
						: null;
				RequestContext context = new RequestContext(req, res, idpMetadata, spMetadata, credential,
						configuration, sessionHandler, bindingHandlerFactory);
				handler.handleGet(context);
			} catch (Exception e) {
				Audit.logError(action, false, e);
				handleError(req, res, e);
			}
		} else {
			throw new UnsupportedOperationException(action + ", allowed: " + handlers.keySet());
		}
	}

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
		try {
			initServlet();
		}
		catch (Exception e) {
			e.printStackTrace();
		}

		String action = req.getRequestURI().substring(req.getRequestURI().lastIndexOf("/") + 1);
		Audit.init(req);

		// This is needed if DispatcherServlet isn't protected
		// by the SPFilter
		if (handlers.containsKey(action)) {
			try {
				SAMLHandler handler = handlers.get(action);
				SessionHandler sessionHandler = sessionHandlerFactory != null ? sessionHandlerFactory.getHandler() : null;
				RequestContext context = new RequestContext(req, res, idpMetadata, spMetadata, credential, configuration, sessionHandler, bindingHandlerFactory);
				handler.handlePost(context);
			}
			catch (Exception e) {
				Audit.logError(action, false, e);
				handleError(req, res, e);
			}
		}
		else {
			throw new UnsupportedOperationException(action);
		}
	}

	public void setInitialized(boolean b) {
		initialized = b;
	}

	public boolean isInitialized() {
		return initialized;
	}

	public final void setCredential(Credential credential) {
		this.credential = credential;
	}

	public final void setConfiguration(Configuration systemConfiguration) {
		this.configuration = systemConfiguration;
	}

	public final void setSPMetadata(SPMetadata metadata) {
		this.spMetadata = metadata;
	}

	public final void setIdPMetadata(IdpMetadata metadata) {
		this.idpMetadata = metadata;
	}

	public void setHandler(SAMLHandler handler, String dispatchPath) {
		handlers.put(dispatchPath, handler);
	}

	public void setBindingHandler(BindingHandlerFactory bindingHandlerFactory) {
		this.bindingHandlerFactory = bindingHandlerFactory;
	}

	public void setSessionHandlerFactory(SessionHandlerFactory sessionHandlerFactory) {
		this.sessionHandlerFactory = sessionHandlerFactory;
	}

	/*
	 * Generic error handling for SAML requests/responses - due to a security
	 * issue with XML Encryption, all error messages are anonymized - so
	 * exception stacktraces and exception messages are no longer shown to the
	 * user (unless configured to do so) - they are still auditlogged though.
	 */
	private void handleError(HttpServletRequest request, HttpServletResponse response, Exception e)
			throws ServletException, IOException {
		String DEFAULT_MESSAGE = "Unable to validate SAML message!";

		log.error("Unable to validate Response", e);

		String err = null;
		if (configuration != null) {
			err = configuration.getString(Constants.PROP_ERROR_SERVLET, null);
		}

		if (err != null) {
			if (configuration.getBoolean(Constants.PROP_SHOW_ERROR, false)) {
				request.setAttribute(Constants.ATTRIBUTE_ERROR, e.getMessage());
				request.setAttribute(Constants.ATTRIBUTE_EXCEPTION, e);
			} else {
				request.setAttribute(Constants.ATTRIBUTE_ERROR, DEFAULT_MESSAGE);
				request.setAttribute(Constants.ATTRIBUTE_EXCEPTION, null);
			}
			request.getRequestDispatcher(err).forward(request, response);
		} else {
			VelocityContext ctx = new VelocityContext();

			if (configuration != null && configuration.getBoolean(Constants.PROP_SHOW_ERROR, false)) {
				ctx.put(Constants.ATTRIBUTE_ERROR, e.getMessage());
				ctx.put(Constants.ATTRIBUTE_EXCEPTION, e);
			} else {
				ctx.put(Constants.ATTRIBUTE_ERROR, DEFAULT_MESSAGE);
				ctx.put(Constants.ATTRIBUTE_EXCEPTION, null);
			}

			response.setContentType("text/html");
			response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);

			try {
				engine.mergeTemplate("error.vm", "UTF-8", ctx, response.getWriter());
			} catch (Exception e1) {
				log.error("Unable to render error template", e1);
				throw new ServletException(e1);
			}
		}

	}

	@Override
	public void destroy() {
		if (sessionHandlerFactory != null) {
			sessionHandlerFactory.close();
		}
		SessionHandlerFactory.Factory.close();
	}

	private class IndexHandler implements SAMLHandler {
		public void handleGet(RequestContext context) throws ServletException, IOException {
			PrintWriter w = context.getResponse().getWriter();

			w.println("<html><head><title>SAML Endppoints</title></head><body><h1>SAML Endpoints</h1>");
			w.println("<ul>");
			for (Map.Entry<String, SAMLHandler> e : handlers.entrySet()) {
				w.println("<li><a href=\"");
				w.print(e.getKey());
				w.print("\">");
				w.print(e.getKey());
				w.print("</a>: ");
				w.print(e.getValue());
				w.println("</li>");
			}
			w.println("</ul>");
			w.println("</body></html>");
		}

		public void handlePost(RequestContext context) throws ServletException, IOException {
		}

	}
}
