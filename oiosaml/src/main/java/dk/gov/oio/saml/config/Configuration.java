package dk.gov.oio.saml.config;

import dk.gov.oio.saml.util.StringUtil;
import org.opensaml.xmlsec.signature.support.SignatureConstants;

import dk.gov.oio.saml.util.InternalException;

public class Configuration {

    // SP configuration
    private String spEntityID; // This SP's EntityID
    private String baseUrl; // The URL endpoint that the DispatcherServlet is working on
    private String servletRoutingPathPrefix; // The endpoint prefix that the DispatcherServlet is working on
    private String servletRoutingPathSuffixError; // The endpoint suffix for error
    private String servletRoutingPathSuffixMetadata; // The endpoint suffix for metadata
    private String servletRoutingPathSuffixLogout; // The endpoint suffix for logout
    private String servletRoutingPathSuffixLogoutResponse; // The endpoint suffix for logout response
    private String servletRoutingPathSuffixAssertion; // The endpoint suffix for assertion
    private String auditLoggerClassName; // Class name of SP's implementation of the AuditLogger adapter
    private String auditRequestAttributeIP; // Replace IP in audit request with value from attribute [protocol:name]
    private String auditRequestAttributePort; // Replace IP in audit request with value from attribute [protocol:name]
    private String auditRequestAttributeSessionId; // Replace SessionId in audit request with value from attribute [protocol:name]
    private String auditRequestAttributeServiceProviderUserId; // Replace ServiceProviderUserId in audit request with value from attribute [protocol:name]
    private String sessionHandlerFactoryClassName; // Class name of the session handler factory implementation
    private String sessionHandlerJndiName; // JNDI name for the JNDI session handler factory
    private String sessionHandlerJdbcUrl; // JDBC URL for the JDBC session handler factory
    private String sessionHandlerJdbcUsername; // JDBC username for the JDBC session handler factory
    private String sessionHandlerJdbcPassword; // JDBC password for the JDBC session handler factory
    private String sessionHandlerJdbcDriverClassName; // JDBC driver class name for the JDBC session handler factory
    private int sessionHandlerInMemoryMaxNumberOfTrackedAssertionIds; // InMemory limit to list of stored assertions
    private boolean validationEnabled = true;
    private boolean isAssuranceLevelAllowed = false;
    private int minimumAssuranceLevel = 3;
    private String contactEmail;

    // Metadata configuration
    private String idpEntityID; // This IdP's EntityID
    private String idpMetadataUrl; // The URL for the IdP Metadata
    private String idpMetadataFile; // The file path for a metadata file
    private int idpMetadataMinRefreshDelay = 1; // The minimum refresh delay in hours
    private int idpMetadataMaxRefreshDelay = 12; // The maximum refresh delay in hours

    // Keystore configuration
    private String keystoreLocation; // Location of the keystore
    private String keystorePassword; // Password to the keystore
    private String keyAlias; // Alias for the keypair

    // Secondary Keystore configuration
    private String secondaryKeystoreLocation; // Location of the keystore
    private String secondaryKeystorePassword; // Password to the keystore
    private String secondaryKeyAlias; // Alias for the keypair

    // Other settings
    private String signatureAlgorithm = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256;
    private int clockSkew = 5;
    private String errorPage;
    private String logoutPage;
    private String loginPage;
    private String nameIDFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
    private boolean supportSelfSigned = false;

    // Revocation check settings
    private boolean crlCheckEnabled = true;
    private boolean ocspCheckEnabled = true;

    // AppSwitch return URL settings
    private String appSwitchReturnURLForAndroid;
    private String appSwitchReturnURLForIOS;

    private Configuration() {

    }

    public String getSpEntityID() {
        return spEntityID;
    }

    public void setSpEntityID(String spEntityID) {
        this.spEntityID = spEntityID;
    }

    public boolean isValidationEnabled() {
        return validationEnabled;
    }

    public void setValidationEnabled(boolean validationEnabled) {
        this.validationEnabled = validationEnabled;
    }

    public boolean isAssuranceLevelAllowed() {
        return isAssuranceLevelAllowed;
    }

    public void setAssuranceLevelAllowed(boolean isAssuranceLevelThreeAllowed) {
        this.isAssuranceLevelAllowed = isAssuranceLevelThreeAllowed;
    }

    public int getMinimumAssuranceLevel() {
        return minimumAssuranceLevel;
    }

    public void setMinimumAssuranceLevel(int minimumAssuranceLevel) {
        this.minimumAssuranceLevel = minimumAssuranceLevel;
    }

    public String getContactEmail() {
        return contactEmail;
    }

    public void setContactEmail(String contactEmail) {
        this.contactEmail = contactEmail;
    }

    public String getIdpEntityID() {
        return idpEntityID;
    }

    public void setIdpEntityID(String idpEntityID) {
        this.idpEntityID = idpEntityID;
    }

    public String getIdpMetadataUrl() {
        return idpMetadataUrl;
    }

    public void setIdpMetadataUrl(String idpMetadataUrl) {
        this.idpMetadataUrl = idpMetadataUrl;
    }

    public String getIdpMetadataFile() {
        return idpMetadataFile;
    }

    public void setIdpMetadataFile(String idpMetadataFile) {
        this.idpMetadataFile = idpMetadataFile;
    }

    public int getIdpMetadataMinRefreshDelay() {
        return idpMetadataMinRefreshDelay;
    }

    public void setIdpMetadataMinRefreshDelay(int idpMetadataMinRefreshDelay) {
        this.idpMetadataMinRefreshDelay = idpMetadataMinRefreshDelay;
    }

    public int getIdpMetadataMaxRefreshDelay() {
        return idpMetadataMaxRefreshDelay;
    }

    public void setIdpMetadataMaxRefreshDelay(int idpMetadataMaxRefreshDelay) {
        this.idpMetadataMaxRefreshDelay = idpMetadataMaxRefreshDelay;
    }

    public String getKeystoreLocation() {
        return keystoreLocation;
    }

    public void setKeystoreLocation(String keystoreLocation) {
        this.keystoreLocation = keystoreLocation;
    }

    public String getKeystorePassword() {
        return keystorePassword;
    }

    public void setKeystorePassword(String keystorePassword) {
        this.keystorePassword = keystorePassword;
    }

    public String getKeyAlias() {
        return keyAlias;
    }

    public void setKeyAlias(String keyAlias) {
        this.keyAlias = keyAlias;
    }

    public String getSecondaryKeystoreLocation() {
        return secondaryKeystoreLocation;
    }

    public void setSecondaryKeystoreLocation(String secondaryKeystoreLocation) {
        this.secondaryKeystoreLocation = secondaryKeystoreLocation;
    }

    public String getSecondaryKeystorePassword() {
        return secondaryKeystorePassword;
    }

    public void setSecondaryKeystorePassword(String secondaryKeystorePassword) {
        this.secondaryKeystorePassword = secondaryKeystorePassword;
    }

    public String getSecondaryKeyAlias() {
        return secondaryKeyAlias;
    }

    public void setSecondaryKeyAlias(String secondaryKeyAlias) {
        this.secondaryKeyAlias = secondaryKeyAlias;
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public boolean isSupportSelfSigned() {
        return supportSelfSigned;
    }

    public void setSupportSelfSigned(boolean supportSelfSigned) {
        this.supportSelfSigned = supportSelfSigned;
    }

    public int getClockSkew() {
        return clockSkew;
    }

    public void setClockSkew(int clockSkew) {
        this.clockSkew = clockSkew;
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public void setBaseURL(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public String getServletRoutingPathPrefix() {
        return servletRoutingPathPrefix;
    }

    public void setServletRoutingPathPrefix(String servletRoutingPathPrefix) {
        this.servletRoutingPathPrefix = servletRoutingPathPrefix;
    }

    public String getServletRoutingPathSuffixError() {
        return servletRoutingPathSuffixError;
    }

    public void setServletRoutingPathSuffixError(String servletRoutingPathSuffixError) {
        this.servletRoutingPathSuffixError = servletRoutingPathSuffixError;
    }

    public String getServletRoutingPathSuffixMetadata() {
        return servletRoutingPathSuffixMetadata;
    }

    public void setServletRoutingPathSuffixMetadata(String servletRoutingPathSuffixMetadata) {
        this.servletRoutingPathSuffixMetadata = servletRoutingPathSuffixMetadata;
    }

    public String getServletRoutingPathSuffixLogout() {
        return servletRoutingPathSuffixLogout;
    }

    public void setServletRoutingPathSuffixLogout(String servletRoutingPathSuffixLogout) {
        this.servletRoutingPathSuffixLogout = servletRoutingPathSuffixLogout;
    }

    public String getServletRoutingPathSuffixLogoutResponse() {
        return servletRoutingPathSuffixLogoutResponse;
    }

    public void setServletRoutingPathSuffixLogoutResponse(String servletRoutingPathSuffixLogoutResponse) {
        this.servletRoutingPathSuffixLogoutResponse = servletRoutingPathSuffixLogoutResponse;
    }

    public String getServletRoutingPathSuffixAssertion() {
        return servletRoutingPathSuffixAssertion;
    }

    public void setServletRoutingPathSuffixAssertion(String servletRoutingPathSuffixAssertion) {
        this.servletRoutingPathSuffixAssertion = servletRoutingPathSuffixAssertion;
    }

    public String getErrorPage() {
        return errorPage;
    }

    public void setErrorPage(String errorPage) {
        this.errorPage = errorPage;
    }

    public String getLogoutPage() {
        return logoutPage;
    }

    public void setLogoutPage(String logoutPage) {
        this.logoutPage = logoutPage;
    }

    public String getLoginPage() {
        return loginPage;
    }

    public void setLoginPage(String loginPage) {
        this.loginPage = loginPage;
    }

    public String getNameIDFormat() {
        return nameIDFormat;
    }

    public void setNameIDFormat(String nameIDFormat) {
        this.nameIDFormat = nameIDFormat;
    }

    public boolean isCRLCheckEnabled() {
        return crlCheckEnabled;
    }

    public void setCRLCheckEnabled(boolean crlCheckEnabled) {
        this.crlCheckEnabled = crlCheckEnabled;
    }

    public boolean isOcspCheckEnabled() {
        return ocspCheckEnabled;
    }

    public void setOcspCheckEnabled(boolean ocspCheckEnabled) {
        this.ocspCheckEnabled = ocspCheckEnabled;
    }

    public String getAuditLoggerClassName() {
        return this.auditLoggerClassName;
    }

    public void setAuditLoggerClassName(String auditLoggerClassName) {
        this.auditLoggerClassName = auditLoggerClassName;
    }

    public String getAuditRequestAttributeIP() {
        return auditRequestAttributeIP;
    }

    public void setAuditRequestAttributeIP(String auditRequestAttributeIP) {
        this.auditRequestAttributeIP = auditRequestAttributeIP;
    }

    public String getAuditRequestAttributePort() {
        return auditRequestAttributePort;
    }

    public void setAuditRequestAttributePort(String auditRequestAttributePort) {
        this.auditRequestAttributePort = auditRequestAttributePort;
    }

    public String getAuditRequestAttributeSessionId() {
        return auditRequestAttributeSessionId;
    }

    public void setAuditRequestAttributeSessionId(String auditRequestAttributeSessionId) {
        this.auditRequestAttributeSessionId = auditRequestAttributeSessionId;
    }

    public String getAuditRequestAttributeServiceProviderUserId() {
        return auditRequestAttributeServiceProviderUserId;
    }

    public void setAuditRequestAttributeServiceProviderUserId(String auditRequestAttributeServiceProviderUserId) {
        this.auditRequestAttributeServiceProviderUserId = auditRequestAttributeServiceProviderUserId;
    }

    public String getSessionHandlerFactoryClassName() {
        return sessionHandlerFactoryClassName;
    }

    public void setSessionHandlerFactoryClassName(String sessionHandlerFactoryClassName) {
        this.sessionHandlerFactoryClassName = sessionHandlerFactoryClassName;
    }

    public String getSessionHandlerJndiName() {
        return sessionHandlerJndiName;
    }

    public void setSessionHandlerJndiName(String sessionHandlerJndiName) {
        this.sessionHandlerJndiName = sessionHandlerJndiName;
    }

    public String getSessionHandlerJdbcUrl() {
        return sessionHandlerJdbcUrl;
    }

    public void setSessionHandlerJdbcUrl(String sessionHandlerJdbcUrl) {
        this.sessionHandlerJdbcUrl = sessionHandlerJdbcUrl;
    }

    public String getSessionHandlerJdbcUsername() {
        return sessionHandlerJdbcUsername;
    }

    public void setSessionHandlerJdbcUsername(String sessionHandlerJdbcUsername) {
        this.sessionHandlerJdbcUsername = sessionHandlerJdbcUsername;
    }

    public String getSessionHandlerJdbcPassword() {
        return sessionHandlerJdbcPassword;
    }

    public void setSessionHandlerJdbcPassword(String sessionHandlerJdbcPassword) {
        this.sessionHandlerJdbcPassword = sessionHandlerJdbcPassword;
    }

    public String getSessionHandlerJdbcDriverClassName() {
        return sessionHandlerJdbcDriverClassName;
    }

    public void setSessionHandlerJdbcDriverClassName(String sessionHandlerJdbcDriverClassName) {
        this.sessionHandlerJdbcDriverClassName = sessionHandlerJdbcDriverClassName;
    }

    public void setSessionHandlerInMemoryMaxNumberOfTrackedAssertionIds(Integer sessionHandlerInMemoryMaxNumberOfTrackedAssertionIds) {
        this.sessionHandlerInMemoryMaxNumberOfTrackedAssertionIds = sessionHandlerInMemoryMaxNumberOfTrackedAssertionIds;
    }

    public int getSessionHandlerInMemoryMaxNumberOfTrackedAssertionIds() {
        return sessionHandlerInMemoryMaxNumberOfTrackedAssertionIds;
    }

    public void setAppSwitchReturnURLForAndroid(String returnURL) {
        this.appSwitchReturnURLForAndroid = returnURL;
    }

    public void setAppSwitchReturnURLForIOS(String returnURL) {
        this.appSwitchReturnURLForIOS = returnURL;
    }

    public String getAppSwitchReturnURLForAndroid() {
        return this.appSwitchReturnURLForAndroid;
    }

    public String getAppSwitchReturnURLForIOS() {
        return this.appSwitchReturnURLForIOS;
    }

    // Configuration builder for mandatory fields
    public static class Builder {
        private String spEntityID;
        private String baseUrl;
        private String idpEntityID;
        private String idpMetadataUrl;
        private String idpMetadataFile;
        private String keystoreLocation;
        private String keystorePassword;
        private String keyAlias;
        private String servletRoutingPathPrefix;
        private String servletRoutingPathSuffixError;
        private String servletRoutingPathSuffixMetadata;
        private String servletRoutingPathSuffixLogout;
        private String servletRoutingPathSuffixLogoutResponse;
        private String servletRoutingPathSuffixAssertion;
        private String auditLoggerClassName;
        private String auditRequestAttributeIP;
        private String auditRequestAttributePort;
        private String auditRequestAttributeSessionId;
        private String auditRequestAttributeServiceProviderUserId;
        private String sessionHandlerFactoryClassName;
        private String sessionHandlerJndiName;
        private String sessionHandlerJdbcUrl;
        private String sessionHandlerJdbcUsername;
        private String sessionHandlerJdbcPassword;
        private String sessionHandlerJdbcDriverClassName;

        public Configuration build() throws InternalException {
            if (StringUtil.isEmpty(spEntityID)) {
                throw new InternalException("Cannot create configuration without SP's entityID");
            }

            if (StringUtil.isEmpty(baseUrl)) {
                throw new InternalException("Cannot create configuration without knowing the Base URL");
            }

            if (StringUtil.isEmpty(idpEntityID)) {
                throw new InternalException("Cannot create configuration without IdP's entityID");
            }

            if (StringUtil.isEmpty(idpMetadataUrl) && StringUtil.isEmpty(idpMetadataFile)) {
                throw new InternalException("Cannot create configuration without IdP Metadata URL or File location");
            }

            if (StringUtil.isEmpty(keystoreLocation)) {
                throw new InternalException("Cannot create configuration without knowing the location of the keystore");
            }

            if (StringUtil.isEmpty(keystorePassword)) {
                throw new InternalException("Cannot create configuration without knowing the password to the keystore");
            }

            if (StringUtil.isEmpty(keyAlias)) {
                throw new InternalException("Cannot create configuration without knowing the alias used inside the keystore");
            }

            // Create configuration
            Configuration configuration = new Configuration();
            configuration.spEntityID = this.spEntityID;
            configuration.baseUrl = this.baseUrl;
            configuration.idpEntityID = this.idpEntityID;
            configuration.idpMetadataUrl = this.idpMetadataUrl;
            configuration.idpMetadataFile = this.idpMetadataFile;
            configuration.keystoreLocation = this.keystoreLocation;
            configuration.keystorePassword = this.keystorePassword;
            configuration.keyAlias = this.keyAlias;
            configuration.servletRoutingPathPrefix = StringUtil.defaultIfEmpty(this.servletRoutingPathPrefix,"saml");
            configuration.servletRoutingPathSuffixError = StringUtil.defaultIfEmpty(this.servletRoutingPathSuffixError, "error");
            configuration.servletRoutingPathSuffixMetadata = StringUtil.defaultIfEmpty(this.servletRoutingPathSuffixMetadata, "metadata");
            configuration.servletRoutingPathSuffixLogout = StringUtil.defaultIfEmpty(this.servletRoutingPathSuffixLogout, "logout");
            configuration.servletRoutingPathSuffixLogoutResponse = StringUtil.defaultIfEmpty(this.servletRoutingPathSuffixLogoutResponse, "logoutResponse");
            configuration.servletRoutingPathSuffixAssertion = StringUtil.defaultIfEmpty(this.servletRoutingPathSuffixAssertion, "assertionConsumer");
            configuration.auditLoggerClassName = StringUtil.defaultIfEmpty(this.auditLoggerClassName, "dk.gov.oio.saml.audit.Slf4JAuditLogger");
            configuration.auditRequestAttributeIP = StringUtil.defaultIfEmpty(this.auditRequestAttributeIP, "request:remoteAddr");
            configuration.auditRequestAttributePort = StringUtil.defaultIfEmpty(this.auditRequestAttributePort, "request:remotePort");
            configuration.auditRequestAttributeSessionId = StringUtil.defaultIfEmpty(this.auditRequestAttributeSessionId, "request:remoteUser");
            configuration.auditRequestAttributeServiceProviderUserId = StringUtil.defaultIfEmpty(this.auditRequestAttributeServiceProviderUserId, "request:sessionId");
            configuration.sessionHandlerFactoryClassName = StringUtil.defaultIfEmpty(this.sessionHandlerFactoryClassName, null);
            configuration.sessionHandlerJndiName = StringUtil.defaultIfEmpty(this.sessionHandlerJndiName, null);
            configuration.sessionHandlerJdbcUrl = StringUtil.defaultIfEmpty(this.sessionHandlerJdbcUrl, null);
            configuration.sessionHandlerJdbcUsername = StringUtil.defaultIfEmpty(this.sessionHandlerJdbcUsername, null);
            configuration.sessionHandlerJdbcPassword = StringUtil.defaultIfEmpty(this.sessionHandlerJdbcPassword, null);
            configuration.sessionHandlerJdbcDriverClassName = StringUtil.defaultIfEmpty(this.sessionHandlerJdbcDriverClassName, null);

            return configuration;
        }

        public Builder setSpEntityID(String spEntityID) {
            this.spEntityID = spEntityID;
            return this;
        }

        public Builder setBaseUrl(String baseUrl) {
            this.baseUrl = baseUrl;
            return this;
        }

        public Builder setIdpEntityID(String idpEntityID) {
            this.idpEntityID = idpEntityID;
            return this;
        }

        public Builder setIdpMetadataUrl(String idpMetadataUrl) {
            this.idpMetadataUrl = idpMetadataUrl;
            return this;
        }
        
        public Builder setIdpMetadataFile(String idpMetadataFile) {
            this.idpMetadataFile = idpMetadataFile;
            return this;
        }

        public Builder setKeystoreLocation(String keystoreLocation) {
            this.keystoreLocation = keystoreLocation;
            return this;
        }

        public Builder setKeystorePassword(String keystorePassword) {
            this.keystorePassword = keystorePassword;
            return this;
        }

        public Builder setKeyAlias(String keyAlias) {
            this.keyAlias = keyAlias;
            return this;
        }
        
        public Builder setServletRoutingPathPrefix(String servletRoutingPathPrefix) {
            this.servletRoutingPathPrefix = servletRoutingPathPrefix;
            return this;
        }
        
        public Builder setServletRoutingPathSuffixError(String servletRoutingPathSuffixError) {
            this.servletRoutingPathSuffixError = servletRoutingPathSuffixError;
            return this;
        }
        
        public Builder setServletRoutingPathSuffixMetadata(String servletRoutingPathSuffixMetadata) {
            this.servletRoutingPathSuffixMetadata = servletRoutingPathSuffixMetadata;
            return this;
        }
        
        public Builder setServletRoutingPathSuffixLogout(String servletRoutingPathSuffixLogout) {
            this.servletRoutingPathSuffixLogout = servletRoutingPathSuffixLogout;
            return this;
        }
        
        public Builder setServletRoutingPathSuffixLogoutResponse(String servletRoutingPathSuffixLogoutResponse) {
            this.servletRoutingPathSuffixLogoutResponse=servletRoutingPathSuffixLogoutResponse;
            return this;
        }
        
        public Builder setServletRoutingPathSuffixAssertion(String servletRoutingPathSuffixAssertion) {
            this.servletRoutingPathSuffixAssertion=servletRoutingPathSuffixAssertion;
            return this;
        }

        public Builder setAuditLoggerClassName(String auditLoggerClassName) {
            this.auditLoggerClassName = auditLoggerClassName;
            return this;
        }

        public Builder setAuditRequestAttributeIP(String auditRequestAttributeIP) {
            this.auditRequestAttributeIP=auditRequestAttributeIP;
            return this;
        }

        public Builder setAuditRequestAttributePort(String auditRequestAttributePort) {
            this.auditRequestAttributePort=auditRequestAttributePort;
            return this;
        }

        public Builder setAuditRequestAttributeSessionId(String auditRequestAttributeSessionId) {
            this.auditRequestAttributeSessionId=auditRequestAttributeSessionId;
            return this;
        }

        public Builder setAuditRequestAttributeServiceProviderUserId(String auditRequestAttributeServiceProviderUserId) {
            this.auditRequestAttributeServiceProviderUserId=auditRequestAttributeServiceProviderUserId;
            return this;
        }

        public Builder setSessionHandlerFactoryClassName(String sessionHandlerFactoryClassName) {
            this.sessionHandlerFactoryClassName=sessionHandlerFactoryClassName;
            return this;
        }

        public Builder setSessionHandlerJndiName(String sessionHandlerJndiName) {
            this.sessionHandlerJndiName=sessionHandlerJndiName;
            return this;
        }

        public Builder setSessionHandlerJdbcUrl(String sessionHandlerJdbcUrl) {
            this.sessionHandlerJdbcUrl = sessionHandlerJdbcUrl;
            return this;
        }

        public Builder setSessionHandlerJdbcUsername(String sessionHandlerJdbcUsername) {
            this.sessionHandlerJdbcUsername = sessionHandlerJdbcUsername;
            return this;
        }

        public Builder setSessionHandlerJdbcPassword(String sessionHandlerJdbcPassword) {
            this.sessionHandlerJdbcPassword = sessionHandlerJdbcPassword;
            return this;
        }

        public Builder setSessionHandlerJdbcDriverClassName(String sessionHandlerJdbcDriverClassName) {
            this.sessionHandlerJdbcDriverClassName = sessionHandlerJdbcDriverClassName;
            return this;
        }
    }

    public boolean isAssuranceLevelSufficient(String value) {
        if(value == null || value.length() < 1 || !isAssuranceLevelAllowed) {
            return false;
        }

        Integer i;
        try {
            i = Integer.parseInt(value);
        } catch (Exception ex) {
            return false;
        }

        return i >= minimumAssuranceLevel;
    }

    public String getServletAssertionConsumerURL() {
        return String.format("%s/%s/%s",baseUrl,servletRoutingPathPrefix,servletRoutingPathSuffixAssertion);
    }

    public String getServletErrorURL() {
        return String.format("%s/%s/%s",baseUrl,servletRoutingPathPrefix,servletRoutingPathSuffixError);
    }

    public String getServletLogoutURL() {
        return String.format("%s/%s/%s",baseUrl,servletRoutingPathPrefix,servletRoutingPathSuffixLogout);
    }

    public String getServletLogoutResponseURL() {
        return String.format("%s/%s/%s",baseUrl,servletRoutingPathPrefix,servletRoutingPathSuffixLogoutResponse);
    }

    public String getServletMetadataURL() {
        return String.format("%s/%s/%s",baseUrl,servletRoutingPathPrefix,servletRoutingPathSuffixMetadata);
    }
}
