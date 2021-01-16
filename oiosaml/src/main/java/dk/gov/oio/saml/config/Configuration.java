package dk.gov.oio.saml.config;

import org.opensaml.xmlsec.signature.support.SignatureConstants;

import dk.gov.oio.saml.util.InternalException;

public class Configuration {

    // SP configuration
    private String spEntityID; // This SP's EntityID
    private String baseUrl; // The URL endpoint that the DispatcherServlet is working on
    private boolean validationEnabled = true;
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
	private String nameIDFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName";
    private boolean supportSelfSigned = false;

    // CRL settings
	private boolean crlCheckEnabled = true;
    private String ocspCaCertificate = "oces-prod-ca.pem";

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

    public String getOcspCaCertificate() {
		return ocspCaCertificate;
	}

	public void setOcspCaCertificate(String ocspCaCertificate) {
		this.ocspCaCertificate = ocspCaCertificate;
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
    }
}
