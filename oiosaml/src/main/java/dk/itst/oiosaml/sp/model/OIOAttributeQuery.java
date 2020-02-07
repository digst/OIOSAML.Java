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
package dk.itst.oiosaml.sp.model;

import java.io.IOException;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Collections;

import dk.itst.oiosaml.logging.Logger;
import dk.itst.oiosaml.logging.LoggerFactory;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeQuery;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Subject;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.security.credential.Credential;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.logging.Audit;
import dk.itst.oiosaml.logging.Operation;
import dk.itst.oiosaml.sp.NameIDFormat;
import dk.itst.oiosaml.sp.model.validation.ValidationException;
import dk.itst.oiosaml.sp.service.util.SOAPClient;
import dk.itst.oiosaml.sp.service.util.Utils;

public class OIOAttributeQuery extends OIORequest {
	private static final Logger log = LoggerFactory.getLogger(OIOAttributeQuery.class);
	
	private final AttributeQuery request;

	public OIOAttributeQuery(AttributeQuery request) {
		super(request);
		this.request = request;
	}

	public static OIOAttributeQuery newQuery(String endpointLocation, String nameId, NameIDFormat format, String spEntityId) {
		
		org.opensaml.saml2.core.AttributeQuery q = SAMLUtil.buildXMLObject(org.opensaml.saml2.core.AttributeQuery.class);
		q.setVersion(SAMLVersion.VERSION_20);
		
		Subject subject = SAMLUtil.createSubject(nameId, endpointLocation, new DateTime().plusMinutes(5));
		subject.getSubjectConfirmations().clear();
		subject.getNameID().setFormat(format.getFormat());
		
		q.setSubject(subject);
		
		q.setDestination(endpointLocation);
		q.setIssueInstant(new DateTime());
		q.setID(Utils.generateUUID());
		q.setIssuer(SAMLUtil.createIssuer(spEntityId));
		q.setConsent("urn:oasis:names:tc:SAML:2.0:consent:current-implicit");
		
		return new OIOAttributeQuery(q);
	}
	
	public void addAttribute(String name, String format) {
		Attribute a = SAMLUtil.buildXMLObject(Attribute.class);
		a.setName(name);
		a.setNameFormat(format);
		request.getAttributes().add(a);
	}

	public OIOAssertion executeQuery(SOAPClient client, Credential credential, String username, String password, boolean ignoreCertPath, Certificate idpCertificate, boolean allowUnencryptedAssertion) throws IOException {
		return executeQuery(client, credential, username, password, ignoreCertPath, Collections.singletonList(idpCertificate), allowUnencryptedAssertion);
	}
	
	public OIOAssertion executeQuery(SOAPClient client, Credential credential, String username, String password, boolean ignoreCertPath, Collection<? extends Certificate> idpCertificates, boolean allowUnencryptedAssertion) throws IOException {
		try {
			sign(credential);
			Audit.log(Operation.ATTRIBUTEQUERY, true, getID(), toXML());
			
			XMLObject res = client.wsCall(this, getDestination(), username, password, ignoreCertPath);
			if (!(res instanceof Response)) throw new IllegalStateException("Received wrong type from IdP (expected Response): " + res);
			
			OIOResponse oiores = new OIOResponse((Response) res);
			if (log.isDebugEnabled()) log.debug("Received attribute query response: " + oiores.toXML());
			
			Audit.log(Operation.ATTRIBUTEQUERY, false, getID(), oiores.toXML());

			oiores.validateResponse(null, idpCertificates, false);
			oiores.decryptAssertion(credential, allowUnencryptedAssertion);
			oiores.validateAssertionSignature(idpCertificates);
			
			return oiores.getAssertion();
		} catch (ValidationException e) {
			Audit.logError(Operation.ATTRIBUTEQUERY, false, getID(), e);
			throw e;
		}
	}
	
}
