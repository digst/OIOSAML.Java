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
 *
 */
package dk.itst.oiosaml.common;

import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.xml.Namespace;

/**
 * Interface with a variety of constants used in the brs-common project for accessing SAML objects
 *
 */
public interface OIOSAMLConstants {
    /** BRS SAML 2.0 XML Namespace */
	
    public final static String BRS_NS = "http://www.eogs.dk/2007/07/brs";
    public final static String XS_NS = "http://www.w3.org/2001/XMLSchema";
    
    /** BRS SAML 2.0 QName prefix */
    public final static String BRS_PREFIX ="brs";
    public final static String XS_PREFIX ="xs";
    
    /** Used name spaces */
	public static final Namespace SAML20_NAMESPACE = new Namespace(SAMLConstants.SAML20_NS,SAMLConstants.SAML20_PREFIX);	
    
	/** AunthContextClassRef urn */
	public static final String PASSWORD_AUTHN_CONTEXT_CLASS_REF = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password";
	public static final String X509_AUTHN_CONTEXT_CLASS_REF = "urn:oasis:names:tc:SAML:2.0:ac:classes:X509";

	/** Subject Confirmation Methods */
	public static final String METHOD_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
	public static final String METHOD_HOK = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key";
	
	public static final String RETRIEVAL_METHOD_ENCRYPTED_KEY = "http://www.w3.org/2001/04/xmlenc#EncryptedKey";
	
	
	/** Format of NameId */
	public static final String PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";

	/** Hashing algorithms */
    public static final String SHA_HASH_ALGORHTM = "SHA-1";
	public static final String SHA1_WITH_RSA = "SHA1withRSA";
	public static final String SHA256_WITH_RSA = "SHA256withRSA";
    
    /** Code format */
    public static final String UTF_8 = "UTF-8";
    
	public static final String URI_ATTRIBUTE_NAME_FORMAT = Attribute.BASIC;

	/** Name and friendly name of all the feasible BRS SAML Attributes */
	public static final String ATTRIBUTE_SURNAME_NAME = "urn:oid:2.5.4.4";

	public static final String ATTRIBUTE_SURNAME_FRIENDLY_NAME = "surName";

	public static final String ATTRIBUTE_COMMON_NAME_NAME = "urn:oid:2.5.4.3";

	public static final String ATTRIBUTE_COMMON_NAME_FRIENDLY_NAME = "CommonName";

	public static final String ATTRIBUTE_UID_NAME = "urn:oid:0.9.2342.19200300.100.1.1";

	public static final String ATTRIBUTE_UID_FRIENDLY_NAME = "uid";

	public static final String ATTRIBUTE_MAIL_NAME = "urn:oid:0.9.2342.19200300.100.1.3";

	public static final String ATTRIBUTE_MAIL_FRIENDLY_NAME = "mail";

	public static final String ATTRIBUTE_TELEPHONE_NUMBER_IDENTIFIER_NAME = "dk:gov:virk:saml:attribute:TelephoneNumberIdentifier";

	public static final String ATTRIBUTE_TELEPHONE_NUMBER_IDENTIFIER_FRIENDLY_NAME = "TelephoneNumberIdentifier";

	public static final String ATTRIBUTE_MOBILE_NUMBER_IDENTIFIER_NAME = "dk:gov:virk:saml:attribute:MobileNumberIdentifier";

	public static final String ATTRIBUTE_MOBILE_NUMBER_IDENTIFIER_FRIENDLY_NAME = "MobileNumberIdentifier";

	public static final String ATTRIBUTE_CVR_NUMBER_IDENTIFIER_NAME = "dk:gov:saml:attribute:CvrNumberIdentifier";

	public static final String ATTRIBUTE_CVR_NUMBER_IDENTIFIER_FRIENDLY_NAME = "CVRnumberIdentifier";

	public static final String ATTRIBUTE_PRODUCTION_UNIT_IDENTIFIER_NAME = "dk:gov:virk:saml:attribute:ProductionUnitIdentifier";

	public static final String ATTRIBUTE_PRODUCTION_UNIT_IDENTIFIER_FRIENDLY_NAME = "ProductionUnitIdentifier";

	public static final String ATTRIBUTE_SERIAL_NUMBER_NAME = "urn:oid:2.5.4.5";

	public static final String ATTRIBUTE_SERIAL_NUMBER_FRIENDLY_NAME = "serialNumber";

	public static final String ATTRIBUTE_PID_NUMBER_IDENTIFIER_NAME = "dk:gov:saml:attribute:PidNumberIdentifier";

	public static final String ATTRIBUTE_PID_NUMBER_IDENTIFIER_FRIENDLY_NAME = "PidNumberIdentifier";

	public static final String ATTRIBUTE_RID_NUMBER_IDENTIFIER_NAME = "dk:gov:saml:attribute:RidNumberIdentifier";

    public static final String ATTRIBUTE_PRIVILEGES_INTERMEDIATE = "dk:gov:saml:attribute:Privileges_intermediate";

    public static final String ATTRIBUTE_USER_ADMINISTRATOR_INDICATOR = "dk:gov:saml:attribute:UserAdministratorIndicator";

	public static final String ATTRIBUTE_RID_NUMBER_IDENTIFIER_FRIENDLY_NAME = "RidNumberIdentifier";

	public static final String ATTRIBUTE_USER_CERTIFICATE_NAME = "urn:oid:1.3.6.1.4.1.1466.115.121.1.8";

	public static final String ATTRIBUTE_USER_CERTIFICATE_FRIENDLY_NAME = "userCertificate";

	public static final String ATTRIBUTE_ASSURANCE_LEVEL_NAME = "dk:gov:saml:attribute:AssuranceLevel";
	
	public static final String ATTRIBUTE_NSIS_LEVEL_NAME = "https://data.gov.dk/concept/core/nsis/loa";
	
	public static final String ATTRIBUTE_EID_PROFESSIONAL_CVR = "https://data.gov.dk/model/core/eid/professional/cvr";

	public static final String ATTRIBUTE_EID_PROFESSIONAL_ORGNAME = "https://data.gov.dk/model/core/eid/professional/orgName";

	public static final String ATTRIBUTE_ASSURANCE_LEVEL_FRIENDLY_NAME = "AssuranceLevel";

	public static final String ATTRIBUTE_CURRENT_CVR_NUMBER_IDENTIFIER_NAME = "dk:gov:virk:saml:attribute:CurrentCVRnumberIdentifier";

	public static final String ATTRIBUTE_CURRENT_CVR_NUMBER_IDENTIFIER_FRIENDLY_NAME = "CurrentCVRnumberIdentifier";

	public static final String ATTRIBUTE_ORGANISATION_NAME_NAME = "urn:oid:2.5.4.10";
	
	public static final String ATTRIBUTE_ORGANISATION_UNIT_NAME = "urn:oid:2.5.4.11";
	
	public static final String ATTRIBUTE_POSTAL_ADDRESS_NAME = "urn:oid:2.5.4.16";
	
	public static final String ATTRIBUTE_SPECVER_NAME = "dk:gov:saml:attribute:SpecVer";
	
	public static final String ATTRIBUTE_TITLE_NAME = "urn:oid:2.5.4.12";
	
	public static final String ATTRIBUTE_UNIQUE_ACCOUNT_KEY_NAME = "dk:gov:saml:attribute:UniqueAccountKey";
	
	public static final String ATTRIBUTE_CPR_NUMBER_NAME = "dk:gov:saml:attribute:CprNumberIdentifier";
	
	public static final String ATTRIBUTE_PSEUDONYM_NAME = "urn:oid:2.5.4.65";
	
	public static final String ATTRIBUTE_YOUTH_CERTIFICATE_NAME = "dk:gov:saml:attribute:IsYouthCert";
	
    public static final String ATTRIBUTE_CERTIFICATE_ISSUER = "urn:oid:2.5.29.29";
	
    public static final String NAMEIDFORMAT_X509SUBJECTNAME = "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName";
    
    public static final String PROFILE_PERSON = "https://data.gov.dk/eid/Person";
    
    public static final String PROFILE_PROFESSIONAL = "https://data.gov.dk/eid/Professional";
    
    public static final String NSIS_REQUEST_LEVEL_LOW = "https://data.gov.dk/concept/core/nsis/loa/Low";
    
    public static final String NSIS_REQUEST_LEVEL_SUBSTANTIAL = "https://data.gov.dk/concept/core/nsis/loa/Substantial";
    
    public static final String NSIS_REQUEST_LEVEL_HIGH = "https://data.gov.dk/concept/core/nsis/loa/High";
    
    public static final String NSIS_RESPONSE_LEVEL_LOW = "Low";
    
    public static final String NSIS_RESPONSE_LEVEL_SUBSTANTIAL = "Substantial";
    
    public static final String NSIS_RESPONSE_LEVEL_HIGH = "High";
}
