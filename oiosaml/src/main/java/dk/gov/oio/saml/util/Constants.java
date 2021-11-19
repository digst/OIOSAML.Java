package dk.gov.oio.saml.util;

public class Constants {

    // Session constants
    public static final String SESSION_NAME_ID = "oiosaml.nameid.value";
    public static final String SESSION_NAME_ID_FORMAT = "oiosaml.nameid.format";
    public static final String SESSION_NSIS_LEVEL = "oiosaml.nsis.level";
    public static final String SESSION_ASSURANCE_LEVEL = "oiosaml.assurance.level";
    public static final String SESSION_REQUESTED_PATH = "oiosaml.request.path";
    public static final String SESSION_AUTHN_REQUEST = "oiosaml.authn.request";
    public static final String SESSION_AUTHENTICATED = "oiosaml.authenticated";
    public static final String SESSION_ASSERTION = "oiosaml.assertion";
    public static final String SESSION_ERROR_TYPE = "oiosaml.error.type";
    public static final String SESSION_ERROR_MESSAGE = "oiosaml.error.message";
	public static final String SESSION_SESSION_INDEX = "oiosaml.session.index";

    // Configuration constants for DispatcherServlet (required)
    public static final String SP_ENTITY_ID = "oiosaml.servlet.entityid";
    public static final String SP_BASE_URL = "oiosaml.servlet.baseurl";
    public static final String SP_ROUTING_BASE = "oiosaml.servlet.routing.path.prefix";
    public static final String SP_ROUTING_ERROR = "oiosaml.servlet.routing.path.suffix.error";
    public static final String SP_ROUTING_METADATA = "oiosaml.servlet.routing.path.suffix.metadata";
    public static final String SP_ROUTING_LOGOUT = "oiosaml.servlet.routing.path.suffix.logout";
    public static final String SP_ROUTING_LOGOUT_RESPONSE = "oiosaml.servlet.routing.path.suffix.logoutResponse";
    public static final String SP_ROUTING_ASSERTION = "oiosaml.servlet.routing.path.suffix.assertion";
    public static final String KEYSTORE_LOCATION = "oiosaml.servlet.keystore.location";
    public static final String KEYSTORE_PASSWORD = "oiosaml.servlet.keystore.password";
    public static final String KEY_ALIAS = "oiosaml.servlet.keystore.alias";
    public static final String IDP_ENTITY_ID = "oiosaml.servlet.idp.entityid";
    public static final String IDP_METADATA_FILE = "oiosaml.servlet.idp.metadata.file";
    public static final String IDP_METADATA_URL = "oiosaml.servlet.idp.metadata.url";

    // Configuration constants for DispatcherServlet (optional, has default values)
	public static final String EXTERNAL_CONFIGURATION_FILE = "oiosaml.servlet.configurationfile";
    public static final String OIOSAML_VALIDATION_ENABLED = "oiosaml.servlet.profile.validation.enabled";
    public static final String OIOSAML_ASSURANCE_LEVEL_ALLOWED = "oiosaml.servlet.profile.validation.assurancelevel.allowed";
    public static final String OIOSAML_ASSURANCE_LEVEL_MINIMUM = "oiosaml.servlet.profile.validation.assurancelevel.minimum";
    public static final String METADATA_NAMEID_FORMAT = "oiosaml.servlet.metadata.nameid.format";
    public static final String METADATA_CONTACT_EMAIL = "oiosaml.servlet.metadata.contact.email";
    public static final String IDP_METADATA_MIN_REFRESH = "oiosaml.servlet.idp.metadata.refresh.min";
    public static final String IDP_METADATA_MAX_REFRESH = "oiosaml.servlet.idp.metadata.refresh.max";
    public static final String SECONDARY_KEYSTORE_LOCATION = "oiosaml.servlet.secondary.keystore.location";
    public static final String SECONDARY_KEYSTORE_PASSWORD = "oiosaml.servlet.secondary.keystore.password";
    public static final String SECONDARY_KEY_ALIAS = "oiosaml.servlet.secondary.keystore.alias";
    public static final String SIGNATURE_ALGORITHM = "oiosaml.servlet.signature.algorithm";
    public static final String ERROR_PAGE = "oiosaml.servlet.secondary.page.error";
    public static final String LOGOUT_PAGE = "oiosaml.servlet.secondary.page.logout";
    public static final String LOGIN_PAGE = "oiosaml.servlet.secondary.page.login";
    public static final String SUPPORT_SELF_SIGNED = "oiosaml.servlet.trust.selfsigned.certs";

    // Configuration constants for revocation check settings
    public static final String CRL_CHECK_ENABLED = "oiosaml.servlet.revocation.crl.check.enabled";
    public static final String OCSP_CHECK_ENABLED = "oiosaml.servlet.revocation.ocsp.check.enabled";

    // Configuration constants for AuthenticationFilter
	public static final String IS_PASSIVE = "oiosaml.filter.ispassive.enabled";
	public static final String FORCE_AUTHN = "oiosaml.filter.forceauthn.enabled";
    public static final String REQUIRED_NSIS_LEVEL = "oiosaml.filter.nsis.required";
    public static final String ATTRIBUTE_PROFILE = "oiosaml.filter.attribute.profile";

    // Configuration values for AuthenticationFilter
    public static final String ATTRIBUTE_PROFILE_PERSON = "https://data.gov.dk/eid/Person";
    public static final String ATTRIBUTE_PROFILE_PROFESSIONAL = "https://data.gov.dk/eid/Professional";


    // SAML Attributes constants
    public static final String SPEC_VER = "https://data.gov.dk/model/core/specVersion";
    public static final String SPEC_VER_VAL = "OIO-SAML-3.0";
    public static final String PRIVILEGE_ATTRIBUTE = "https://data.gov.dk/model/core/eid/privilegesIntermediate";
    public static final String LOA = "https://data.gov.dk/concept/core/nsis/loa";
    public static final String CVR_NUMBER = "https://data.gov.dk/model/core/eid/professional/cvr";
    public static final String ORGANIZATION_NAME = "https://data.gov.dk/model/core/eid/professional/orgName";
    public static final String ASSURANCE_LEVEL = "dk:gov:saml:attribute:AssuranceLevel";
}
