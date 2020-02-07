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
package dk.itst.oiosaml.sp.model.validation;

import java.io.IOException;

import javax.xml.parsers.ParserConfigurationException;

import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.xml.io.UnmarshallingException;
import org.xml.sax.SAXException;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.sp.AbstractTests;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.model.OIOAssertionTest;

public class OIOSAMLAssertionValidatorTest extends AbstractTests {
	private static final String serviceProviderEntityId = "poc3.eogs.capgemini.dk.spref";
	private static final String assertionConsumerURL = "http://jre-mac.trifork.com:8080/saml/SAMLAssertionConsumer";

	private OIOAssertion assertion;
	private OIOSAMLAssertionValidator validator;

	@Before
	public void setUp() throws SAXException, IOException, ParserConfigurationException, UnmarshallingException {
		Assertion assertion = (Assertion) SAMLUtil.unmarshallElement(OIOAssertionTest.class.getResourceAsStream("/assertion.xml"));

		assertion.getAuthnStatements().get(0).setSessionNotOnOrAfter(new DateTime().plus(60000));
		assertion.getConditions().setNotOnOrAfter(new DateTime().plus(60000));
		assertion.getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData().setNotOnOrAfter(new DateTime().plus(60000));
		
		this.assertion = new OIOAssertion(assertion);
		validator = new OIOSAMLAssertionValidator();
	}

	@Test
	public void testValidate() {
		assertion.validateAssertion(validator, serviceProviderEntityId, assertionConsumerURL);
	}

}
