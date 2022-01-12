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

import dk.gov.oio.saml.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.opensaml.core.config.InitializationException;

import dk.gov.oio.saml.config.Configuration;
import dk.gov.oio.saml.service.OIOSAML3Service;
import dk.gov.oio.saml.servlet.ErrorHandler.ERROR_TYPE;
import dk.gov.oio.saml.util.Constants;
import dk.gov.oio.saml.util.ExternalException;
import dk.gov.oio.saml.util.InternalException;

public class DispatcherServlet extends HttpServlet {
    private static final long serialVersionUID = -9177718057493368235L;
    private static final Logger log = LoggerFactory.getLogger(DispatcherServlet.class);
    private Map<String, SAMLHandler> handlers;
    private boolean initialized = false;

    @Override
    public void init(ServletConfig servletConfig) throws ServletException {
        log.debug("Initializing DispatcherServlet");

        super.init(servletConfig);
        initServlet();

        log.debug("Initialized DispatcherServlet");
    }

    private void handleOptionalValues(Map<String, String> config, Configuration configuration) {
        String value = config.get(Constants.OIOSAML_VALIDATION_ENABLED);
        if (StringUtil.isNotEmpty(value)) {
            configuration.setValidationEnabled("true".equals(value));
        }

        value = config.get(Constants.OIOSAML_ASSURANCE_LEVEL_ALLOWED);
        if(StringUtil.isNotEmpty(value)) {
            configuration.setAssuranceLevelAllowed("true".equals(value));
        }

        value = config.get(Constants.OIOSAML_ASSURANCE_LEVEL_MINIMUM);
        if (StringUtil.isNotEmpty(value)) {
            try {
                Integer i = Integer.parseInt(value);
                configuration.setMinimumAssuranceLevel(i);
            }
            catch (Exception ex) {
                log.error("Invalid value {} = {}", Constants.OIOSAML_ASSURANCE_LEVEL_MINIMUM, value, ex);
            }
        }
        
        value = config.get(Constants.SUPPORT_SELF_SIGNED);
        if (StringUtil.isNotEmpty(value)) {
            configuration.setSupportSelfSigned("true".equals(value));
        }
        
        value = config.get(Constants.CRL_CHECK_ENABLED);
        if (StringUtil.isNotEmpty(value)) {
            configuration.setCRLCheckEnabled("true".equals(value));
        }
        
        value = config.get(Constants.OCSP_CHECK_ENABLED);
        if (StringUtil.isNotEmpty(value)) {
            configuration.setOcspCheckEnabled("true".equals(value));
        }

        value = config.get(Constants.METADATA_NAMEID_FORMAT);
        if (StringUtil.isNotEmpty(value)) {
            configuration.setNameIDFormat(value);
        }

        value = config.get(Constants.METADATA_CONTACT_EMAIL);
        if (StringUtil.isNotEmpty(value)) {
            configuration.setContactEmail(value);
        }
        
        value = config.get(Constants.ERROR_PAGE);
        if (StringUtil.isNotEmpty(value)) {
            configuration.setErrorPage(value);
        }
        
        value = config.get(Constants.LOGIN_PAGE);
        if (StringUtil.isNotEmpty(value)) {
            configuration.setLoginPage(value);
        }
        
        value = config.get(Constants.LOGOUT_PAGE);
        if (StringUtil.isNotEmpty(value)) {
            configuration.setLogoutPage(value);
        }
        
        value = config.get(Constants.IDP_METADATA_MIN_REFRESH);
        if (StringUtil.isNotEmpty(value)) {
            try {
                Integer i = Integer.parseInt(value);
                configuration.setIdpMetadataMinRefreshDelay(i);
            }
            catch (Exception ex) {
                log.error("Invalid value {} = {}", Constants.IDP_METADATA_MIN_REFRESH, value, ex);
            }
        }
        
        value = config.get(Constants.IDP_METADATA_MAX_REFRESH);
        if (StringUtil.isNotEmpty(value)) {
            try {
                Integer i = Integer.parseInt(value);
                configuration.setIdpMetadataMaxRefreshDelay(i);
            }
            catch (Exception ex) {
                log.error("Invalid value {} = {}", Constants.IDP_METADATA_MAX_REFRESH, value, ex);
            }
        }

        value = config.get(Constants.SECONDARY_KEY_ALIAS);
        if (StringUtil.isNotEmpty(value)) {
            configuration.setSecondaryKeyAlias(value);
        }

        value = config.get(Constants.SECONDARY_KEYSTORE_LOCATION);
        if (StringUtil.isNotEmpty(value)) {
            configuration.setSecondaryKeystoreLocation(value);
        }

        value = config.get(Constants.SECONDARY_KEYSTORE_PASSWORD);
        if (StringUtil.isNotEmpty(value)) {
            configuration.setSecondaryKeystorePassword(value);
        }
        
        value = config.get(Constants.SIGNATURE_ALGORITHM);
        if (StringUtil.isNotEmpty(value)) {
            configuration.setSignatureAlgorithm(value);
        }

        value = config.get(Constants.SP_SESSION_HANDLER_NUM_TRACKED_ASSERTIONIDS);
        try {
            configuration.setSessionHandlerNumTrackedSessionIds(Integer.parseInt(StringUtil.defaultIfEmpty(value,"10000")));
        }
        catch (Exception ex) {
            log.error("Invalid value {} = {}", Constants.SP_SESSION_HANDLER_NUM_TRACKED_ASSERTIONIDS, value, ex);
        }
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
        if (log.isDebugEnabled()) {
            log.debug("Received GET ({}{})", req.getServletPath(), req.getContextPath());
        }

        if (!initialized) {
            initServlet();
        }

        // Find endpoint
        Configuration config = OIOSAML3Service.getConfig();
        String[] split = req.getRequestURI().split("/"+config.getServletRoutingPathPrefix()+"/");
        String action = split[split.length - 1];

        SAMLHandler samlHandler = handlers.get(action);
        if (samlHandler == null) {
            log.error("No handler registered for action: {}", action);
            
            ErrorHandler.handle(req, res, ERROR_TYPE.CONFIGURATION_ERROR, "No handler registered for action: " + action);
            return;
        }

        log.debug("Selected MessageHandler: {}", samlHandler.getClass().getName());

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
            log.debug("Received GET ({}{})", req.getServletPath(), req.getContextPath());
        }

        if (!initialized) {
            initServlet();
        }

        // Find endpoint
        Configuration config = OIOSAML3Service.getConfig();
        String[] split = req.getRequestURI().split("/"+config.getServletRoutingPathPrefix()+"/");
        String action = split[split.length - 1];

        SAMLHandler samlHandler = handlers.get(action);
        if (samlHandler == null) {
            log.error("No handler registered for action: {}", action);
            
            ErrorHandler.handle(req, res, ERROR_TYPE.CONFIGURATION_ERROR, "No handler registered for action: " + action);
            return;
        }

        log.debug("Selected MessageHandler: {}", samlHandler.getClass().getName());

        try {
            if (StringUtil.isNotEmpty(req.getHeader("SOAPAction"))) {
                samlHandler.handleSOAP(req, res);
            } else {
                samlHandler.handlePost(req, res);
            }
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

    private Map<String, String> getInitConfig() {
        HashMap<String, String> configMap = new HashMap<>();
        Enumeration<String> keys = this.getInitParameterNames();
        while (keys.hasMoreElements()) {
            String key = keys.nextElement();
            String value = this.getInitParameter(key);
            configMap.put(key, value);
        }

        // load external configuration if one is supplied
        String externalConfigurationFile = configMap.get(Constants.EXTERNAL_CONFIGURATION_FILE);
        if (StringUtil.isNotEmpty(externalConfigurationFile)) {
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
                log.error("Failed to load external configuration file: {}", externalConfigurationFile, ex);
            }
        }

        return configMap;
    }
    
    // Should make sure all handlers are initialized and added to the list
    private void initServlet() throws ServletException {
        if (!initialized) {
            // convert to more useful map
            Map<String, String> config = getInitConfig();

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
                        .setServletRoutingPathPrefix(config.get(Constants.SP_ROUTING_BASE))
                        .setServletRoutingPathSuffixError(config.get(Constants.SP_ROUTING_ERROR))
                        .setServletRoutingPathSuffixMetadata(config.get(Constants.SP_ROUTING_METADATA))
                        .setServletRoutingPathSuffixLogout(config.get(Constants.SP_ROUTING_LOGOUT))
                        .setServletRoutingPathSuffixLogoutResponse(config.get(Constants.SP_ROUTING_LOGOUT_RESPONSE))
                        .setServletRoutingPathSuffixAssertion(config.get(Constants.SP_ROUTING_ASSERTION))
                        .setAuditLoggerClassName(config.get(Constants.SP_AUDIT_CLASSNAME))
                        .setAuditRequestAttributeIP(config.get(Constants.SP_AUDIT_ATTRIBUTE_IP))
                        .setAuditRequestAttributePort(config.get(Constants.SP_AUDIT_ATTRIBUTE_PORT))
                        .setAuditRequestAttributeServiceProviderUserId(config.get(Constants.SP_AUDIT_ATTRIBUTE_USER_ID))
                        .setAuditRequestAttributeSessionId(config.get(Constants.SP_AUDIT_ATTRIBUTE_SESSION_ID))
                        .setSessionHandlerFactoryClassName(config.get(Constants.SP_SESSION_HANDLER_FACTORY_CLASSNAME))
                        .setSessionHandlerJndiName(config.get(Constants.SP_SESSION_HANDLER_JNDI_NAME))
                        .setSessionHandlerJdbcUrl(config.get(Constants.SP_SESSION_HANDLER_JDBC_URL))
                        .setSessionHandlerJdbcUsername(config.get(Constants.SP_SESSION_HANDLER_JDBC_USERNAME))
                        .setSessionHandlerJdbcPassword(config.get(Constants.SP_SESSION_HANDLER_JDBC_PASSWORD))
                        .setSessionHandlerJdbcDriverClassName(config.get(Constants.SP_SESSION_HANDLER_JDBC_DRIVER_CLASSNAME))
                        .build();

                handleOptionalValues(config, configuration);

                OIOSAML3Service.init(configuration);

                handlers = new HashMap<>();
                handlers.put(configuration.getServletRoutingPathSuffixError(), new ErrorHandler());
                handlers.put(configuration.getServletRoutingPathSuffixMetadata(), new MetadataHandler());
                handlers.put(configuration.getServletRoutingPathSuffixLogout(), new LogoutRequestHandler());
                handlers.put(configuration.getServletRoutingPathSuffixLogoutResponse(), new LogoutResponseHandler());
                handlers.put(configuration.getServletRoutingPathSuffixAssertion(), new AssertionHandler());

                initialized = true;
            }
            catch (InternalException | InitializationException e) {
                throw new ServletException(e);
            }
        }
    }
}
