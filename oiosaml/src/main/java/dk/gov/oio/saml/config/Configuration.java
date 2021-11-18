package dk.gov.oio.saml.config;

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

        public Configuration build() throws InternalException {
            if (spEntityID == null || spEntityID.length() == 0) {
                throw new InternalException("Cannot create configuration without SP's entityID");
            }

            if (baseUrl == null || baseUrl.length() == 0) {
                throw new InternalException("Cannot create configuration without knowing the Base URL");
            }

            if (idpEntityID == null) {
                throw new InternalException("Cannot create configuration without IdP's entityID");
            }

            if ((idpMetadataUrl == null || idpMetadataUrl.length() == 0) &&
                (idpMetadataFile == null || idpMetadataFile.length() == 0)) {
                throw new InternalException("Cannot create configuration without IdP Metadata URL or File location");
            }

            if (keystoreLocation == null || keystoreLocation.length() == 0) {
                throw new InternalException("Cannot create configuration without knowing the location of the keystore");
            }

            if (keystorePassword == null || keystorePassword.length() == 0) {
                throw new InternalException("Cannot create configuration without knowing the password to the keystore");
            }

            if (keyAlias == null || keyAlias.length() == 0) {
                throw new InternalException("Cannot create configuration without knowing the alias used inside the keystore");
            }

            if (servletRoutingPathPrefix == null || servletRoutingPathPrefix.length() == 0) {
                servletRoutingPathPrefix = "saml";
            }

            if (servletRoutingPathSuffixError == null || servletRoutingPathSuffixError.length() == 0) {
                servletRoutingPathSuffixError = "error";
            }

            if (servletRoutingPathSuffixMetadata == null || servletRoutingPathSuffixMetadata.length() == 0) {
                servletRoutingPathSuffixMetadata = "metadata";
            }

            if (servletRoutingPathSuffixLogout == null || servletRoutingPathSuffixLogout.length() == 0) {
                servletRoutingPathSuffixLogout = "logout";
            }

            if (servletRoutingPathSuffixLogoutResponse == null || servletRoutingPathSuffixLogoutResponse.length() == 0) {
                servletRoutingPathSuffixLogoutResponse = "logoutResponse";
            }

            if (servletRoutingPathSuffixAssertion == null || servletRoutingPathSuffixAssertion.length() == 0) {
                servletRoutingPathSuffixAssertion = "assertionConsumer";
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
            configuration.servletRoutingPathPrefix = this.servletRoutingPathPrefix;
            configuration.servletRoutingPathSuffixError = this.servletRoutingPathSuffixError;
            configuration.servletRoutingPathSuffixMetadata = this.servletRoutingPathSuffixMetadata;
            configuration.servletRoutingPathSuffixLogout = this.servletRoutingPathSuffixLogout;
            configuration.servletRoutingPathSuffixLogoutResponse = this.servletRoutingPathSuffixLogoutResponse;
            configuration.servletRoutingPathSuffixAssertion = this.servletRoutingPathSuffixAssertion;

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
