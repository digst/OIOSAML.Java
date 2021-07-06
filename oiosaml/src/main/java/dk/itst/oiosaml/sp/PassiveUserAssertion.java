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

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;

public class PassiveUserAssertion implements UserAssertion {
	
	private final String userId;

	public PassiveUserAssertion(String userId) {
		this.userId = userId;
	}

	public Collection<UserAttribute> getAllAttributes() {
		return Collections.unmodifiableCollection(new ArrayList<UserAttribute>());
	}

	public String getAssertionId() {
		return null;
	}

	public int getAssuranceLevel() {
		return 0;
	}

	public UserAttribute getAttribute(String name) {
		return null;
	}

	public String getCPRNumber() {
		return null;
	}

	public String getCVRNumberIdentifier() {
		return null;
	}

	public String getCertificateSerialNumber() {
		return null;
	}

	public String getCommonName() {
		return null;
	}

	public Date getIssueTime() {
		return new Date();
	}

	public String getIssuer() {
		return null;
	}

	public String getMail() {
		return null;
	}

	public NameIDFormat getNameIDFormat() {
		return NameIDFormat.UNSPECIFIED;
	}

	public String getOrganizationName() {
		return null;
	}

	public String getOrganizationUnit() {
		return null;
	}

	public String getPIDNumber() {
		return null;
	}

	public String getPostalAddress() {
		return null;
	}

	public String getPseudonym() {
		return null;
	}

	public String getRIDNumber() {
		return null;
	}

	public Date getSessionExpireTime() {
		return null;
	}

	public String getSpecificationVersion() {
		return null;
	}

	public String getSubject() {
		return userId;
	}

	public String getSurname() {
		return null;
	}

	public String getTitle() {
		return null;
	}

	public String getUniqueAccountKey() {
		return null;
	}

	public X509Certificate getUserCertificate() {
		return null;
	}

	public String getUserId() {
		return userId;
	}

	public String getXML() {
		return "";
	}

	public boolean isAuthenticated() {
		return false;
	}

	public boolean isOCESProfileCompliant() {
		return false;
	}

	public boolean isOIOSAMLCompliant() {
		return false;
	}

	public boolean isPersistentPseudonymProfileCompliant() {
		return false;
	}

	public boolean isSigned() {
		return false;
	}

	public Boolean isYouthCertificate() {
		return null;
	}

}
