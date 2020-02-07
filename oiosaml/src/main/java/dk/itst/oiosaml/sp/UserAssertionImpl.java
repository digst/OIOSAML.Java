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
package dk.itst.oiosaml.sp;

import dk.itst.oiosaml.common.OIOSAMLConstants;
import dk.itst.oiosaml.oiobpp.PrivilegeList;
import dk.itst.oiosaml.security.SecurityHelper;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.util.AttributeUtil;
import org.joda.time.DateTime;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;

import java.io.Serializable;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class UserAssertionImpl implements UserAssertion, Serializable {
	private static final long serialVersionUID = -1756335950388129831L;
	private Map<String, UserAttribute> attributes = new HashMap<String, UserAttribute>();
	private Date issueTime;
	private String issuer;
	private Date sessionExpireTime;
	private NameIDFormat nameIDFormat;
	private String nameID;
	private boolean signed;
	private String xml;
	private String id;
	private PrivilegeList privilegeList;

	public UserAssertionImpl(OIOAssertion assertion) {
		for (AttributeStatement attrStatement : assertion.getAssertion().getAttributeStatements()) {
			for (Attribute attr : attrStatement.getAttributes()) {
				if(attributes.containsKey(attr.getName())){
					UserAttribute userAttribute = attributes.get(attr.getName());
					List<String> values = AttributeUtil.extractAttributeValueValues(attr);
					for (String value : values){
						userAttribute.getValues().add(value);
					}
				}
				else {
					attributes.put(attr.getName(), new UserAttribute(attr.getName(), attr.getFriendlyName(), AttributeUtil.extractAttributeValueValues(attr), attr.getNameFormat()));
				}
			}
		}
		id = assertion.getID();
		
		this.privilegeList = assertion.getPrivilegeList();
		
		if (assertion.getAssertion().getIssueInstant() != null) {
			issueTime = assertion.getAssertion().getIssueInstant().toDate();
		}
		if (assertion.getAssertion().getIssuer() != null) {
			issuer = assertion.getAssertion().getIssuer().getValue();
		}
		if (!assertion.getAssertion().getAuthnStatements().isEmpty()) {
			DateTime expireTime = assertion.getAssertion().getAuthnStatements().get(0).getSessionNotOnOrAfter();
			if (expireTime != null) {
				sessionExpireTime = expireTime.toDate();
			}
		}
		if (assertion.getAssertion().getSubject() != null) {
			nameIDFormat = NameIDFormat.getNameID(assertion.getAssertion().getSubject().getNameID().getFormat());
			nameID = assertion.getAssertion().getSubject().getNameID().getValue();
		}
		signed = assertion.getAssertion().getSignature() != null;
		try {
			xml = assertion.toXML();
		} catch (Exception e) {}
	}

	public Collection<UserAttribute> getAllAttributes() {
		return Collections.unmodifiableCollection(attributes.values());
	}

	public int getAssuranceLevel() {
		String level = getAttributeValue(OIOSAMLConstants.ATTRIBUTE_ASSURANCE_LEVEL_NAME);
		if (level == null) {
			return 0;
		} else if ("test".equals(level)) {
			return -1;
		} else {
			return Integer.valueOf(level);
		}
	}
	
	public PrivilegeList getPrivilegeList() {
		return privilegeList;
	}

	public String getNSISLevel() {
		return getAttributeValue(OIOSAMLConstants.ATTRIBUTE_NSIS_LEVEL_NAME);
	}
	
	public UserAttribute getAttribute(String name) {
		return attributes.get(name);
	}

	public String getCVRNumberIdentifier() {
		return getAttributeValue(OIOSAMLConstants.ATTRIBUTE_CVR_NUMBER_IDENTIFIER_NAME);
	}

	public String getCertificateSerialNumber() {
		return getAttributeValue(OIOSAMLConstants.ATTRIBUTE_SERIAL_NUMBER_NAME);
	}

	public String getCommonName() {
		return getAttributeValue(OIOSAMLConstants.ATTRIBUTE_COMMON_NAME_NAME);
	}

	public Date getIssueTime() {
		return issueTime;
	}

	public String getIssuer() {
		return issuer;
	}

	public String getMail() {
		return getAttributeValue(OIOSAMLConstants.ATTRIBUTE_MAIL_NAME);
	}

	public NameIDFormat getNameIDFormat() {
		return nameIDFormat;
	}

	public String getOrganizationName() {
		return getAttributeValue(OIOSAMLConstants.ATTRIBUTE_ORGANISATION_NAME_NAME);
	}

	public String getOrganizationUnit() {
		return getAttributeValue(OIOSAMLConstants.ATTRIBUTE_ORGANISATION_UNIT_NAME);
	}

	public String getPostalAddress() {
		return getAttributeValue(OIOSAMLConstants.ATTRIBUTE_POSTAL_ADDRESS_NAME);
	}

	public Date getSessionExpireTime() {
		return sessionExpireTime;
	}

	public String getSpecificationVersion() {
		return getAttributeValue(OIOSAMLConstants.ATTRIBUTE_SPECVER_NAME);
	}

	public String getSubject() {
		return nameID;
	}

	public String getSurname() {
		return getAttributeValue(OIOSAMLConstants.ATTRIBUTE_SURNAME_NAME);
	}

	public String getTitle() {
		return getAttributeValue(OIOSAMLConstants.ATTRIBUTE_TITLE_NAME);
	}

	public String getUniqueAccountKey() {
		return getAttributeValue(OIOSAMLConstants.ATTRIBUTE_UNIQUE_ACCOUNT_KEY_NAME);
	}

	public String getUserId() {
		return getAttributeValue(OIOSAMLConstants.ATTRIBUTE_UID_NAME);
	}

	public String getXML() {
		return xml;
	}

	public boolean isSigned() {
		return signed;
	}

	private String getAttributeValue(String name) {
		UserAttribute attr = attributes.get(name);
		if (attr != null) {
			List<String> values = attr.getValues();
			if(values.size()>0) {
				return values.get(0);
			}
		}
		return null;
	}

	public String getCPRNumber() {
		return getAttributeValue(OIOSAMLConstants.ATTRIBUTE_CPR_NUMBER_NAME);
	}

	public String getRIDNumber() {
		return getAttributeValue(OIOSAMLConstants.ATTRIBUTE_RID_NUMBER_IDENTIFIER_NAME);
	}

	public String getPIDNumber() {
		return getAttributeValue(OIOSAMLConstants.ATTRIBUTE_PID_NUMBER_IDENTIFIER_NAME);
	}

	public String getPseudonym() {
		return getAttributeValue(OIOSAMLConstants.ATTRIBUTE_PSEUDONYM_NAME);
	}

	public X509Certificate getUserCertificate() {
		String val = getAttributeValue(OIOSAMLConstants.ATTRIBUTE_USER_CERTIFICATE_NAME);
		if (val == null) return null;
		
		try {
			return SecurityHelper.buildJavaX509Cert(val);
		} catch (CertificateException e) {
			throw new RuntimeException(e);
		}
	}

	public boolean isOCESProfileCompliant() {
		boolean res = isOIOSAMLCompliant();
		try {
			res &= NameIDFormat.X509SUBJECT.equals(getNameIDFormat());
			res &= getCertificateSerialNumber() != null;
			res &= isYouthCertificate() != null;
			res &= getPIDNumber() != null ^ getRIDNumber() != null;
			
			if (getPIDNumber() != null) {
				res &= ("PID:" + getPIDNumber()).equals(getUserId()); 
			} else if (getRIDNumber() != null) {
				res &= getCVRNumberIdentifier() != null;
				res &= ("CVR:" + getCVRNumberIdentifier() + "-RID:" + getRIDNumber()).equals(getUserId());
			}
			return res;
		} catch (RuntimeException e) {
			return false;
		}
	}

	public boolean isOIOSAMLCompliant() {
		boolean res = true;
		res &= "DK-SAML-2.0".equals(getSpecificationVersion());
		res &= getAssuranceLevel() > 0;
		res &= getSurname() != null;
		res &= getCommonName() != null;
		res &= getUserId() != null;
		res &= getMail() != null;
		return res;
	}

	public boolean isPersistentPseudonymProfileCompliant() {
		boolean res = true;
		res &= "DK-SAML-2.0".equals(getSpecificationVersion());
		res &= getAssuranceLevel() > 0;
		res &= getUserId() == null;
		res &= NameIDFormat.PERSISTENT.equals(getNameIDFormat());
		res &= getPIDNumber() == null;
		res &= getRIDNumber() == null;
		res &= getCertificateSerialNumber() == null;
		res &= getMail() == null;
		res &= getSurname() == null;
		res &= getCommonName() == null;
		
		return res;
	}

	public Boolean isYouthCertificate() {
		String val = getAttributeValue(OIOSAMLConstants.ATTRIBUTE_YOUTH_CERTIFICATE_NAME);
		if (val == null) return null;
		
		return Boolean.valueOf(val);
	}

	public String getAssertionId() {
		return id;
	}

	public boolean isAuthenticated() {
		return true;
	}
}
