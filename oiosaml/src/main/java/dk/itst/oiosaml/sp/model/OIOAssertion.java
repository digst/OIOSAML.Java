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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import dk.itst.oiosaml.logging.Logger;
import dk.itst.oiosaml.logging.LoggerFactory;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;

import dk.itst.oiosaml.common.OIOSAMLConstants;
import dk.itst.oiosaml.sp.model.validation.AssertionValidator;
import dk.itst.oiosaml.sp.model.validation.ValidationException;
import dk.itst.oiosaml.sp.util.AttributeUtil;

public class OIOAssertion extends OIOSamlObject {
	private static final Logger log = LoggerFactory.getLogger(OIOAssertion.class);
	
	private final Assertion assertion;

	public OIOAssertion(Assertion assertion) {
		super(assertion);
		this.assertion = assertion;
	}
	
	public static OIOAssertion fromResponse(Response response) {
		if (response.getAssertions().isEmpty()) {
			throw new RuntimeException("Didn't get an assertion in ArtifactResponse");
		}
		Assertion assertion = response.getAssertions().get(0);
		return new OIOAssertion(assertion);
	}

	/**
	 * Return the value of the /Subject/NameID element in an assertion
	 * 
	 * @return The value. <code>null</code>, if the assertion does not
	 *         contain the element.
	 */
	public String getSubjectNameIDValue() {
		String retVal = null;
    	if (assertion.getSubject() != null && 
        	assertion.getSubject().getNameID() != null) {
        		retVal =  assertion.getSubject().getNameID().getValue();
        }
    	return retVal;
	}
	
	
	/**
	 * Check whether an assertion contains an assertionConsumerURL
	 * within a subjectConfirmationData having the
	 * subjectConfirmationMethod=urn:oasis:names:tc:SAML:2.0:cm:bearer
	 * 
	 * @return <code>true</code>, if the assertion contains the
	 *         assertionConsumerURL. <code>false</code>
	 *         otherwise.
	 */
	public boolean checkRecipient(String assertionConsumerURL) {
		if (assertionConsumerURL == null) return false;
		if (assertion.getSubject() == null) return false;
		if (assertion.getSubject().getSubjectConfirmations() == null) return false;
		
		
		for (SubjectConfirmation subjectConfirmation : assertion.getSubject().getSubjectConfirmations()) {
			if (!OIOSAMLConstants.METHOD_BEARER.equals(subjectConfirmation.getMethod())) continue;

			SubjectConfirmationData subjectConfirmationData = subjectConfirmation.getSubjectConfirmationData();
			if (subjectConfirmationData == null) continue;
			
			if (assertionConsumerURL.equals(subjectConfirmationData.getRecipient())) {
				return true;
			}
		}
		return false;
	}

	public DateTime getConfirmationTime() {
		if (assertion.getSubject() == null) return null;
		if (assertion.getSubject().getSubjectConfirmations() == null || 
				assertion.getSubject().getSubjectConfirmations().isEmpty()) return null;

		for (SubjectConfirmation subjectConfirmation : assertion.getSubject().getSubjectConfirmations()) {
			SubjectConfirmationData data = subjectConfirmation.getSubjectConfirmationData();

			if (data != null && data.getNotOnOrAfter() != null) {
				return data.getNotOnOrAfter();
			}
		}
		return null;
	}

	
	/**
	 * Return the value of the /AuthnStatement@SessionIndex element in an assertion
	 * 
	 * @return The value. <code>null</code>, if the assertion does not
	 *         contain the element.
	 */
	public String getSessionIndex() {
		String retVal = null;
    	if (assertion != null && assertion.getAuthnStatements() != null) {
    		if (assertion.getAuthnStatements().size() > 0) {
    			// We only look into the first AuthnStatement
    			AuthnStatement authnStatement = assertion.getAuthnStatements().get(0);
    			retVal = authnStatement.getSessionIndex();
    		}
    	}
    	return retVal;
	}

	/**
	 * Check whether an assertion contains an expired sessionIndex within a
	 * AuthnStatement (i.e. AuthnStatement@SessionNotOnOrAfter >= now)
	 * 
	 * @return <code>true</code>, if the assertion has expired. <code>false</code>
	 *         otherwise.
	 */
	public boolean hasSessionExpired() {
		boolean retVal = false;
    	if (assertion != null && assertion.getAuthnStatements() != null) {
			if (assertion.getAuthnStatements().size() > 0) {
				// We only look into the first AuthnStatement
				AuthnStatement authnStatement = (AuthnStatement) assertion.getAuthnStatements().get(0);
				if (authnStatement.getSessionNotOnOrAfter() != null) {
					retVal = authnStatement.getSessionNotOnOrAfter().isBeforeNow();
				} else {
					retVal = false;
				}
			}
		}
		return retVal;
	}

	/**
	 * Return the value of the /AuthnStatement/AuthnContext/AuthnContextClassRef
	 * element in an assertion
	 * 
	 * @return The value. <code>null</code>, if the assertion does not
	 *         contain the element.
	 */
	public String getAuthnContextClassRef() {
		String retVal = null;
    	if (assertion.getAuthnStatements() != null) {
    		if (assertion.getAuthnStatements().size() > 0) {
    			// We only look into the first AuthnStatement
    			AuthnStatement authnStatement = (AuthnStatement) assertion.getAuthnStatements().get(0);
    			AuthnContext authnContext = authnStatement.getAuthnContext();
    			if (authnContext != null) {
    				AuthnContextClassRef authnContextClassRef = authnContext.getAuthnContextClassRef();
    				if (authnContextClassRef != null) {
    					retVal = authnContextClassRef.getAuthnContextClassRef();
    				}
    			}
    		}
    	}
    	return retVal;
	}

    /**
     * Validate whether a SAML assertion contains the expected elements
     * @param validator The validator to use forassertion validation. Can be <code>null</code>.
     * @param spEntityID The entityID of the service provider
     * @param spAssertionConsumerURL The assertion consumer URL of the service provider
     */
    public void validateAssertion(AssertionValidator validator, String spEntityID, String spAssertionConsumerURL) throws ValidationException {
    	try {
			assertion.validate(false);
		} catch (org.opensaml.xml.validation.ValidationException e) {
			throw new ValidationException(e);
		}
		// The SAML version must be 2.0
		if (!SAMLVersion.VERSION_20.equals(assertion.getVersion())) {  
			throw new ValidationException("The assertion must be version 2.0. Was " + assertion.getVersion());
		}
    	// There must be an ID
    	if (assertion.getID() == null) {  
    		throw new ValidationException("The assertion must contain a ID");
    	}
    	
    	log.debug("Using validator: " + validator);
    	if (validator != null) {
    		validator.validate(this, spEntityID, spAssertionConsumerURL);
    	}
    }

    public Assertion getAssertion() {
    	return assertion;
    }
    
    public int getAssuranceLevel() {
    	for (AttributeStatement attributeStatement : assertion.getAttributeStatements()) {
    		for (Attribute attribute : attributeStatement.getAttributes()) {
				if (OIOSAMLConstants.ATTRIBUTE_ASSURANCE_LEVEL_NAME.equals(attribute.getName())) {
					String value = AttributeUtil.extractAttributeValueValue(attribute);
					return new AssuranceLevel(value).getValue();
				}
			}
		}
    	return 0;
    }
    
    public String getID() {
    	return assertion.getID();
    }
    
	public boolean isHolderOfKey() {
		if (assertion.getSubject() == null) return false;
		if (assertion.getSubject().getSubjectConfirmations().isEmpty()) return false;
		
		return OIOSAMLConstants.METHOD_HOK.equals(assertion.getSubject().getSubjectConfirmations().get(0).getMethod());
	}
	
	public Collection<String> getAudience() {
		List<String> audiences = new ArrayList<String>();
		
		if (assertion.getConditions() == null) return audiences;
		
		for (AudienceRestriction audienceRestriction : assertion.getConditions().getAudienceRestrictions()) {
			for (Audience audience : audienceRestriction.getAudiences()) {
				audiences.add(audience.getAudienceURI());
			}
		}
		
		return audiences;
	}

	public DateTime getConditionTimeNotOnOrAfter() {
		if (assertion.getConditions() == null) return null;
		
		return assertion.getConditions().getNotOnOrAfter();
	}
	
	public DateTime getConditionTimeNotBefore() {
		if (assertion.getConditions() == null) return null;
		
		return assertion.getConditions().getNotBefore();
	}

	public String getIssuer() {
		return assertion.getIssuer().getValue();
	}
	

}
