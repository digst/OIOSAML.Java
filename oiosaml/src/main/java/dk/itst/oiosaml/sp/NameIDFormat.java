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

/**
 * Standard SAML 2.0 Name ID formats.
 * 
 * @author recht
 *
 */
public enum NameIDFormat {
	UNSPECIFIED("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"),
	EMAIL("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"),
	X509SUBJECT("urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName"),
	WINDOWS_DOMAIN("urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName"),
	KERBEROS_PRINCIPAL("urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos"),
	ENTITY("urn:oasis:names:tc:SAML:2.0:nameid-format:entity"),
	PERSISTENT("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"),
	TRANSIENT("urn:oasis:names:tc:SAML:2.0:nameid-format:transient");	

	private final String format;
	
	private NameIDFormat(String format) {
		this.format = format;
	}
	
	@Override
	public String toString() {
		return super.toString() + ": " + format;
	}
	
	/**
	 * Get the enumeration value from a format URI.
	 * 
	 * @param format SAML 2.0 format.
	 * @throws IllegalArgumentException If the format is not defined in SAML 2.0.
	 */
	public static NameIDFormat getNameID(String format) {
		for (NameIDFormat id : values()) {
			if (id.format.equals(format)) {
				return id;
			}
		}
		throw new IllegalArgumentException("Format " + format + " unknown");
	}

	public String getFormat() {
		return format;
	}
}
