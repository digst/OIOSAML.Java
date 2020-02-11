package dk.itst.oiosaml.idp.util;

public class Constants {
    public static final String AUTHN_REQUEST = "AUTHN_REQUEST";
    public static final String RELAY_STATE = "RelayState";
    public static final String SAMLRequest = "SAMLRequest";

    public static final String ATTRIBUTE_VALUE_FORMAT = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic";

    //Common Attributes
    public static final String SPEC_VERSION = "https://data.gov.dk/model/core/specVersion";
    public static final String SPEC_VERSION_OIOSAML30 = "OIO-SAML-3.0";

    public static final String LEVEL_OF_ASSURANCE = "https://data.gov.dk/concept/core/nsis/loa";
    public static final String LEVEL_OF_ASSURANCE_HIGH = "High";
    public static final String LEVEL_OF_ASSURANCE_SUBSTANTIAL = "Substantial";
    public static final String LEVEL_OF_ASSURANCE_LOW = "Low";

    //Natural Person Attributes


    //Professional Person Attributes
    public static final String CVR = "https://data.gov.dk/model/core/eid/professional/cvr";
    public static final String CVR_VALUE = "20301823";

    public static final String ORGANISATION_NAME = "https://data.gov.dk/model/core/eid/professional/orgName";
    public static final String ORGANISATION_NAME_VALUE = "Digitaliseringsstyrelsen";
}
