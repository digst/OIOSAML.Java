package dk.gov.oio.saml.util;

public class Constants {

    // Session constants
    public static final String SESSION_ERROR_TYPE = "oiosaml.error.type";
    public static final String SESSION_ERROR_MESSAGE = "oiosaml.error.message";

    // Configuration constants for DispatcherServlet (required)
    public static final String SP_ENTITY_ID = "oiosaml.servlet.entityid";
    public static final String SP_BASE_URL = "oiosaml.servlet.baseurl";
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
    public static final String SP_ROUTING_BASE = "oiosaml.servlet.routing.path.prefix";
    public static final String SP_ROUTING_ERROR = "oiosaml.servlet.routing.path.suffix.error";
    public static final String SP_ROUTING_METADATA = "oiosaml.servlet.routing.path.suffix.metadata";
    public static final String SP_ROUTING_LOGOUT = "oiosaml.servlet.routing.path.suffix.logout";
    public static final String SP_ROUTING_LOGOUT_RESPONSE = "oiosaml.servlet.routing.path.suffix.logoutResponse";
    public static final String SP_ROUTING_ASSERTION = "oiosaml.servlet.routing.path.suffix.assertion";
    public static final String SP_AUDIT_CLASSNAME = "oiosaml.servlet.audit.logger.classname";
    public static final String SP_AUDIT_ATTRIBUTE_IP = "oiosaml.servlet.audit.logger.attribute.ip";
    public static final String SP_AUDIT_ATTRIBUTE_PORT = "oiosaml.servlet.audit.logger.attribute.port";
    public static final String SP_AUDIT_ATTRIBUTE_USER_ID = "oiosaml.servlet.audit.logger.attribute.userid";
    public static final String SP_AUDIT_ATTRIBUTE_SESSION_ID = "oiosaml.servlet.audit.logger.attribute.sessionId";
    public static final String SP_SESSION_HANDLER_FACTORY_CLASSNAME ="oiosaml.servlet.session.handler.factory";
    public static final String SP_SESSION_HANDLER_JNDI_NAME ="oiosaml.servlet.session.handler.jdni.name";
    public static final String SP_SESSION_HANDLER_JDBC_URL = "oiosaml.servlet.session.handler.jdbc.url";
    public static final String SP_SESSION_HANDLER_JDBC_USERNAME = "oiosaml.servlet.session.handler.jdbc.username";
    public static final String SP_SESSION_HANDLER_JDBC_PASSWORD = "oiosaml.servlet.session.handler.jdbc.password";
    public static final String SP_SESSION_HANDLER_JDBC_DRIVER_CLASSNAME = "oiosaml.servlet.session.handler.jdbc.driver.classname";
    public static final String SP_SESSION_HANDLER_MAX_NUM_TRACKED_ASSERTIONIDS ="oiosaml.servlet.session.handler.inmemory.max.tracked.assertionids";

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

    // Nemlog-in Public Extensions constants
    public static final String NL_EXTENSIONS_PUBLIC_NAMESPACE = "https://data.gov.dk/eid/saml/extensions";
    public static final String NL_EXTENSIONS_PUBLIC_NAMESPACE_PREFIX = "nl";

    // AppSwitch Constants
    public static final String APPSWITCH_PLATFORM_QUERY_PARAMETER = "appSwitchPlatform";
    public static final String SP_APPSWITCH_RETURNURL_ANDROID = "oiosaml.appswitch.returnurl.android";
    public static final String SP_APPSWITCH_RETURNURL_IOS = "oiosaml.appswitch.returnurl.ios";
}
