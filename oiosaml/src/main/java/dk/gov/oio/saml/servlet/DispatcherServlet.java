package dk.gov.oio.saml.servlet;

import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.opensaml.core.config.InitializationException;

import dk.gov.oio.saml.config.Configuration;
import dk.gov.oio.saml.service.OIOSAML3Service;
import dk.gov.oio.saml.servlet.ErrorHandler.ERROR_TYPE;
import dk.gov.oio.saml.util.Constants;
import dk.gov.oio.saml.util.ExternalException;
import dk.gov.oio.saml.util.InternalException;

public class DispatcherServlet extends HttpServlet {
	private static final long serialVersionUID = -9177718057493368235L;
	private static final Logger log = Logger.getLogger(DispatcherServlet.class);
    private Map<String, SAMLHandler> handlers;
    private boolean initialized = false;

    @Override
    public void init(ServletConfig servletConfig) throws ServletException {
        if (log.isDebugEnabled()) {
            log.debug("Initializing DispatcherServlet");
        }

        // convert to more useful map
        Map<String, String> config = toConfig(servletConfig);
        
        try {
        	// create configuration with mandatory settings
            Configuration configuration = new Configuration.Builder()
                    .setSpEntityID(config.get(Constants.SP_ENTITY_ID))
                    .setBaseUrl(config.get(Constants.SP_BASE_URL))
                    .setKeystoreLocation(config.get(Constants.KEYSTORE_LOCATION))
                    .setKeystorePassword(config.get(Constants.KEYSTORE_PASSWORD))
                    .setKeyAlias(config.get(Constants.KEY_ALIAS))
                    .setIdpEntityID(config.get(Constants.IDP_ENTITY_ID))
                    .setIdpMetadataUrl(config.get(Constants.IDP_METADATA_URL))
                    .setIdpMetadataFile(config.get(Constants.IDP_METADATA_FILE))
                    .build();
            
            handleOptionalValues(config, configuration);
            
            OIOSAML3Service.init(configuration);
        }
        catch (InternalException | InitializationException e) {
            throw new ServletException(e);
        }

        initServlet();

        if (log.isDebugEnabled()) {
            log.debug("Initialized DispatcherServlet");
        }
    }

    private void handleOptionalValues(Map<String, String> config, Configuration configuration) {
        String value = config.get(Constants.OIOSAML_VALIDATION_ENABLED);
        if (value != null && value.length() > 0) {
            configuration.setValidationEnabled("true".equals(value));
        }
        
        value = config.get(Constants.SUPPORT_SELF_SIGNED);
        if (value != null && value.length() > 0) {
            configuration.setSupportSelfSigned("true".equals(value));
        }
        
        value = config.get(Constants.CRL_CHECK_ENABLED);
        if (value != null && value.length() > 0) {
            configuration.setCRLCheckEnabled("true".equals(value));
        }
        
        value = config.get(Constants.OCSP_CHECK_ENABLED);
        if (value != null && value.length() > 0) {
            configuration.setOcspCheckEnabled("true".equals(value));
        }

        value = config.get(Constants.METADATA_NAMEID_FORMAT);
        if (value != null && value.length() > 0) {
        	configuration.setNameIDFormat(value);
        }

        value = config.get(Constants.METADATA_CONTACT_EMAIL);
        if (value != null && value.length() > 0) {
        	configuration.setContactEmail(value);
        }
        
        value = config.get(Constants.ERROR_PAGE);
        if (value != null && value.length() > 0) {
        	configuration.setErrorPage(value);
        }
        
        value = config.get(Constants.LOGIN_PAGE);
        if (value != null && value.length() > 0) {
        	configuration.setLoginPage(value);
        }
        
        value = config.get(Constants.LOGOUT_PAGE);
        if (value != null && value.length() > 0) {
        	configuration.setLogoutPage(value);
        }
        
        value = config.get(Constants.IDP_METADATA_MIN_REFRESH);
        if (value != null && value.length() > 0) {
        	try {
        		Integer i = Integer.parseInt(value);
        		configuration.setIdpMetadataMinRefreshDelay(i);
        	}
        	catch (Exception ex) {
        		log.error("Invalid value " + Constants.IDP_METADATA_MIN_REFRESH + " = " + value, ex);
        	}
        }
        
        value = config.get(Constants.IDP_METADATA_MAX_REFRESH);
        if (value != null && value.length() > 0) {
        	try {
        		Integer i = Integer.parseInt(value);
        		configuration.setIdpMetadataMaxRefreshDelay(i);
        	}
        	catch (Exception ex) {
        		log.error("Invalid value " + Constants.IDP_METADATA_MAX_REFRESH + " = " + value, ex);
        	}
        }

        value = config.get(Constants.SECONDARY_KEY_ALIAS);
        if (value != null && value.length() > 0) {
        	configuration.setSecondaryKeyAlias(value);
        }

        value = config.get(Constants.SECONDARY_KEYSTORE_LOCATION);
        if (value != null && value.length() > 0) {
        	configuration.setSecondaryKeystoreLocation(value);
        }

        value = config.get(Constants.SECONDARY_KEYSTORE_PASSWORD);
        if (value != null && value.length() > 0) {
        	configuration.setSecondaryKeystorePassword(value);
        }
        
        value = config.get(Constants.SIGNATURE_ALGORITHM);
        if (value != null && value.length() > 0) {
        	configuration.setSignatureAlgorithm(value);
        }
	}

	@Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
        if (log.isDebugEnabled()) {
            log.debug("Received GET (" + req.getServletPath() + req.getContextPath() + ")");
        }

        if (!initialized) {
            initServlet();
        }

        // Find endpoint
        String[] split = req.getRequestURI().split("/saml/");
        String action = split[split.length - 1];

        SAMLHandler samlHandler = handlers.get(action);
        if (samlHandler == null) {
        	log.error("No handler registered for action: " + action);
        	
        	ErrorHandler.handle(req, res, ERROR_TYPE.CONFIGURATION_ERROR, "No handler registered for action: " + action);
        	return;
        }

        if (log.isDebugEnabled()) {
            log.debug("Selected MessageHandler: " + samlHandler.getClass().getName());
        }

		try {
			samlHandler.handleGet(req, res);
		}
		catch (ExternalException | InternalException | InitializationException e) {
        	log.error("Unexpected error during SAML processing", e);
        	
        	ErrorHandler.handle(req, res, ERROR_TYPE.EXCEPTION, e.getMessage());
        	return;
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
        if (log.isDebugEnabled()) {
            log.debug("Received GET (" + req.getServletPath() + req.getContextPath() + ")");
        }

        if (!initialized) {
            initServlet();
        }

        // Find endpoint
        String[] split = req.getRequestURI().split("/saml/");
        String action = split[split.length - 1];

        SAMLHandler samlHandler = handlers.get(action);
        if (samlHandler == null) {
        	log.error("No handler registered for action: " + action);
        	
        	ErrorHandler.handle(req, res, ERROR_TYPE.CONFIGURATION_ERROR, "No handler registered for action: " + action);
        	return;
        }

        if (log.isDebugEnabled()) {
            log.debug("Selected MessageHandler: " + samlHandler.getClass().getName());
        }

        try {
            samlHandler.handlePost(req, res);
		}
		catch (ExternalException | InternalException e) {
        	log.error("Unexpected error during SAML processing", e);
        	
        	ErrorHandler.handle(req, res, ERROR_TYPE.EXCEPTION, e.getMessage());
        	return;
		}
    }

    @Override
    protected void doPut(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
        doPost(req, res);
    }

    @Override
    protected void doDelete(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
        doGet(req, res);
    }

    private Map<String, String> toConfig(ServletConfig servletConfig) {
        HashMap<String, String> configMap = new HashMap<>();
        Enumeration<String> keys = servletConfig.getInitParameterNames();
        while (keys.hasMoreElements()) {
            String key = keys.nextElement();
            String value = servletConfig.getInitParameter(key);
            configMap.put(key, value);
        }

        // load external configuration if one is supplied
        String externalConfigurationFile = configMap.get(Constants.EXTERNAL_CONFIGURATION_FILE);
        if (externalConfigurationFile != null && externalConfigurationFile.length() > 0) {
        	try (InputStream is = getClass().getClassLoader().getResourceAsStream(externalConfigurationFile)) {
                Properties p = new Properties();
                p.load(is);
                
                @SuppressWarnings("unchecked")
				Enumeration<String> enums = (Enumeration<String>) p.propertyNames();
                while (enums.hasMoreElements()) {
                  String key = enums.nextElement();
                  String value = p.getProperty(key);
                  
                  configMap.put(key,  value);
                }
        	}
        	catch (Exception ex) {
        		log.error("Failed to load external configuration file: " + externalConfigurationFile, ex);
        	}
        }

        return configMap;
    }
    
    // Should make sure all handlers are initialized and added to the list
    private void initServlet() {
    	if (!initialized) {
	        handlers = new HashMap<>();
	        handlers.put("error", new ErrorHandler());
	        handlers.put("metadata", new MetadataHandler());
	        handlers.put("logout", new LogoutRequestHandler());
	        handlers.put("logoutResponse", new LogoutResponseHandler());
	        handlers.put("assertionConsumer", new AssertionHandler());
	        initialized = true;
    	}
    }
}
