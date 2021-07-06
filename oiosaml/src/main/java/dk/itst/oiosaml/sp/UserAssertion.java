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
import java.util.Collection;
import java.util.Date;

public interface UserAssertion {
	
	/**
	 * @return Whether the Assertion is compliant with OIOSAML version 2.0.5.
	 */
	public boolean isOIOSAMLCompliant();
	
	/**
	 * @return Whether the Assertion is in compliance with the OCES profile in OIOSAML version 2.0.5
	 */
	public boolean isOCESProfileCompliant();
	
	/**
	 * Persistent pseudonyms are used to support federation using persistent
	 * pseudonym identifiers. A pseudonym identifier is in effect a random value that an IdP-
	 * SP pair establishes and uses to refer to the same user. The shared identifier must be
	 * unique to the actual IdP-SP pairing. Each entity maintains a mapping from the shared
	 * identifier to their internal representation. The goal of this attribute profile is to define
	 * the content of assertions and attributes supporting this scenario.
	 * @return Whether the Assertion is an persistent pseudonym.
	 */
	public boolean isPersistentPseudonymProfileCompliant();
	
	/**
	 * @return Raw xml representation of the SAML assertion.
	 **/
	public String getXML();
	
	/**
	 * @return Expiretime for the users session with the Identity Provider (IdP). May be null if IdP does not provide it.
	 */
	public Date getSessionExpireTime();

	/**
	 * @return The time of issue of the assertion.
	 */	
	public Date getIssueTime();

	/**
	 * @return The ID of the Identity Provider
	 */
	public String getIssuer();
	
	/**
	 * @return Whether the assertion is signed. If signed, the signature is also guaranteed to be valid.
	 */
	public boolean isSigned();
	
	/**
	 * @return The Name ID value of the subject Node. Often just the username. Is always present. 
	 */
	public String getSubject();
	
	/**
	 * @return The format of the subject name id. Could be: urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified <br/>
	 * @see #getSubject()
	 */
	public NameIDFormat getNameIDFormat();

	/**
	 * The surname of the subject, attribute: urn:oid:2.5.4.4 <br/>
	 * Mandatory in DK-SAML 2.0.5
	 * @return The Surname of the subject.
	 */
	public String getSurname();
	
	/**
	 * The common name of the subject, attribute: urn:oid:2.5.4.3 <br/>
	 * Mandatory in DK-SAML 2.0.5
	 * 	 * @return The common name of the subject. 
	 */
	public String getCommonName();
	
	/**
	 * The user id attribute of the subject, attribute: urn:oid:0.9.2342.19200300.100.1.1<br/>
	 * The uid attribute specifies the user id in the user s (principal s) home organization (or
	 * credential issuing organization where home organization is unknown or doesn't exist
	 * which is the case for citizens).<br />
	 * The actual content of the uid attribute is left to the discretion of the IdP, and should be
	 * documented by the IdP, unless an OCES certificate was used by the user at login, in which
	 * case the following applies:<br />
	 * In the OCES attribute profile, the following conventions apply for the uid attribute:
	 * The uid attribute must contain the Subject Serial number from the OCES
	 * certificate. The field from the certificate is included literally.
	 * This means that the PID and RID numbers will be present twice in the assertion, but
	 * this may be convenient:<br />
	 * If the Service Provider needs a unique ID within the credential issuing
	 * organization or he needs the Subject Serial Number, he may simply pick the
	 * uid attribute.<br />
	 * If the Service Provider wants to know whether the Subject is a person or
	 * employee or needs the RID/PID/CPR/CVR numbers, he can pick the
	 * corresponding (atomic) attributes without having to parse the serial number
	 * string.<br />
	 * 	 Mandatory in DK-SAML 2.0.5 
	 * @return The user id of the subject. 
	 */
	public String getUserId();
	
	/**
	 * The email of the subject, attribute: urn:oid:0.9.2342.19200300.100.1.3 <br/>
	 * 	 Mandatory in DK-SAML 2.0.5 
	 * @return The email of the subject. 
	 */
	public String getMail();

	/**
	 * The Assurance level of the subject, attribute:  dk:gov:saml:attribute:AssuranceLevel<br/>
	 *  In the xml representation the value may be the string "1", "2", "3", "4", "test", represented here as integers, respectively 1, 2, 3, 4, -1<br />
	 * 	 Mandatory in DK-SAML 2.0.5 <br/>
	 * <a href="http://www.itst.dk/arkitektur-og-standarder/Standardisering/standarder-for-serviceorienteret-infrastruktur/standarder-for-brugerstyring/resolveuid/c180053b937f49169aa82b6d4a839620">Standard defining semantics of assurancelevel</a>
	 *  <ul><li> Niveau 1 - Lille eller ingen tiltro til påstået identitet</li>
	 *   <li>Niveau 2 - Nogen tiltro til påstået identitet</li>
	 *   <li>Niveau 3 - Høj tillid til påstået identitet</li>
	 *   <li>Niveau 4 - Meget høj tillid til påstået identitet</li></ul>

	 * @return The assurance level of the SAML assertion. Defined in "Vejledning vedrørende niveauer af autenticitetssikring"
	 */
	public int getAssuranceLevel();

	/**
	 * The specification version, attribute: dk:gov:saml:attribute:SpecVer.<br />
	 * The SpecVer attribute tells the Service Provider which version of the DK-SAML
	 * profile the assertion was issued under.
	 * @return The specification version of the assertion. 
	 */
	public String getSpecificationVersion();

	/**
	 * The unique account key of the subject, attribute: dk:gov:saml:attribute:UniqueAccountKey.<br />
	 * <b>Not</b> Mandatory in DK-SAML 2.0.5<br />
	 * Subject to these <a href="http://www.itst.dk/arkitektur-og-standarder/Standardisering/standarder-for-serviceorienteret-infrastruktur/standarder-for-brugerstyring/resolveuid/a3d519d0ce1f304eb1b4fc6f7941b027">recommendations</a> 
	 * @return The unique account key of the subject if present, null otherwise 
	 */
	public String getUniqueAccountKey();
	
	/**
	 * The CVR identifier of the subject, attribute: dk:gov:saml:attribute:CvrNumberIdentifier<br />
	 * <b>Not</b> Mandatory in DK-SAML 2.0.5 
	 * @return The CPR identifier of the subject if present, null otherwise. 
	 */
	public String getCVRNumberIdentifier();
			
	/**
	 * Get an attribute on the assertion by the name of the assertion.<br />
	 * @param name of the assertion, e.g. "dk:gov:saml:attribute:CvrNumberIdentifier"
	 * @return the requested attribute (immutable), null if not present.
	 */
	public UserAttribute getAttribute(String name);
	
	/**
	 * Get a list of all attributes in the assertion.
	 * @return Immutable list containing all attributes.
	 */
	public Collection<UserAttribute> getAllAttributes();
	
	/**
	 * Attribute name: urn:oid:2.5.4.5<br />
	 * Mandatory in the OCES profile of DK-SAML 2.0.5
	 * @return The certificate serial number
	 */
	public String getCertificateSerialNumber();
	
	/**
	 * Attribute name: urn:oid:2.5.4.10<br />
	 * Mandatory for companies and employees in the OCES profile of DK-SAML 2.0.5
	 * @return The organization name
	 */
	public String getOrganizationName(); 
	
	/**
	 * The name of the department within an organisation. Attribute name: urn:oid:2.5.4.11<br />
	 * <b>Not</b> mandatory in the OCES profile of DK-SAML 2.0.5
	 * @return The organisation unit.
	 */	
	public String getOrganizationUnit();
	
	/**
	 * Attribute name: urn:oid:2.5.4.12<br />
  	 * <b>Not</b> mandatory in the OCES profile of DK-SAML 2.0.5
  	 * @return the title of the subject (as employee in an organisation)
	 **/
	public String getTitle();
	
	/**
	 * Attribute name: urn:oid:2.5.4.16<br />
  	 * <b>Not</b> mandatory in the OCES profile of DK-SAML 2.0.5
	 * @return the postal address of a company or person.
	 */
	public String getPostalAddress();

	/**
	 * Attribute name: urn:oid:2.5.4.65<br />
  	 * <b>Not</b> mandatory in the OCES profile of DK-SAML 2.0.5
	 * @return pesudonym
	 */	
	public String getPseudonym();
	
	/**
	 * Attribute name: dk:gov:saml:attribute:IsYouthCert<br />
	 * Mandatory in the OCES profile of DK-SAML 2.0.5
	 * @return TRUE if the certificate is a youth certificate, FALSE if not, and null if the attribute was not present.
	 */
	public Boolean isYouthCertificate();
	
	/**
	 * Attribute name: urn:oid:1.3.6.1.4.1.1466.115.121.1.8<br />
  	 * <b>Not</b> mandatory in the OCES profile of DK-SAML 2.0.5
	 * @return The OCES user certificate if provided by the IdP, null otherwise.
	 */
	public X509Certificate getUserCertificate();
	
	/**
	 * For OCES person certificates, the most interesting attribute is the PID number which
	 * contains a unique identifier for the person6. The advantage of PID numbers over CPR
	 * numbers is that they can be freely exchanged without risk of violating personal data
	 * protection acts.<br/>
	 * Attribute name: dk:gov:saml:attribute:PidNumberIdentifier<br />
	 * Mandatory in the OCES profile of DK-SAML 2.0.5
	 * @return The PID number from the OCES certificate presented to the IdP  
	 */
	public String getPIDNumber();
	
	/**
	 * Attribute name: dk:gov:saml:attribute:CprNumberIdentifier<br />
	 * In some scenarios, it may be easier to transfer the CPR number directly in the
	 * assertion. The CPR number attribute is optional and must only be included when:<br/>
     * <ul><li> A formal agreement has been made to exchange it</li>
     *   <li>The Service Provider is authorized to receive it (e.g. is a Government entity)</li>
     *   <li>The surrounding assertion is encrypted (which is mandatory in this profile)</li></ul>
	 * An Identity Provider must have the technical capability to resolve and insert the CPR
	 * number both for citizens and employees who have one7. The CPR number attribute is
	 * however optional such that it can be omitted from assertions for Service Providers
	 * who do not need it / are not allowed receiving it.<br />
  	 * <b>Not</b> mandatory in the OCES profile of DK-SAML 2.0.5
	 * @return The CPR number of the subject if available, null otherwise.
	 */
	public String getCPRNumber();
	
	/**
	 * Attribute name: dk:gov:saml:attribute:RidNumberIdentifier<br /> 
	 * This attribute is mandatory when the user has authenticated with an employee
	 * certificate (syntax and semantics of the number is defined in DS844).<br />
	 * Mandatory for employees in the OCES profile of DK-SAML 2.0.5 
	 * @return The employee number / PID of the employee if present, null otherwise.
	 */
	public String getRIDNumber();
	
	/**
	 * Returns the ID of the assertion.
	 */
	public String getAssertionId();
	
	/**
	 * Checks if the current user is authenticated.
	 * @return <code>true</code> if a valid assertion has been received. <code>false</code> if a valid assertion has not been received, but
	 * the user has been allowed to continue. This can happen if IsPassive is set, and the user was signed on.
	 */
	public boolean isAuthenticated();
	
}
