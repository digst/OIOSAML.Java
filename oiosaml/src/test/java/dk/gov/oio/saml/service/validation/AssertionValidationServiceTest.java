package dk.gov.oio.saml.service.validation;

import dk.gov.oio.saml.model.NSISLevel;
import dk.gov.oio.saml.service.AssertionService;
import dk.gov.oio.saml.service.AuthnRequestService;
import dk.gov.oio.saml.service.BaseServiceTest;
import dk.gov.oio.saml.session.AuthnRequestWrapper;
import dk.gov.oio.saml.util.ExternalException;
import dk.gov.oio.saml.util.IdpUtil;
import dk.gov.oio.saml.util.SamlHelper;
import dk.gov.oio.saml.util.TestConstants;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import org.joda.time.DateTime;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.assertion.AssertionValidationException;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.impl.EncryptedAssertionMarshaller;
import org.opensaml.saml.saml2.core.impl.EncryptedAssertionUnmarshaller;

public class AssertionValidationServiceTest extends BaseServiceTest {

	@DisplayName("Test that validator will pass a valid assertion")
	@Test
	public void testValidateCorrectAssertion() throws Exception {
		AssertionValidationService validationService = new AssertionValidationService();

		// Mock HttpServletRequest
		HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
		Mockito.when(request.getRequestURL()).thenReturn(new StringBuffer(TestConstants.SP_ASSERTION_CONSUMER_URL));

		// Create AuthnRequest
		AuthnRequestService authnRequestService = AuthnRequestService.getInstance();
		AuthnRequest authnRequest = authnRequestService.createAuthnRequest(TestConstants.SP_ASSERTION_CONSUMER_URL, false, false, NSISLevel.SUBSTANTIAL);
		String inResponseToId = authnRequest.getID();

		// Create MessageContext, Response and Assertion
		String nameID = "https://data.gov.dk/model/core/eid/person/uuid/37a5a1aa-67ce-4f70-b7c0-b8e678d585f7";
		MessageContext<SAMLObject> messageContext = IdpUtil.createMessageWithAssertion(true, true, true, nameID, TestConstants.SP_ENTITY_ID, TestConstants.SP_ASSERTION_CONSUMER_URL, inResponseToId);
		Response response = (Response) messageContext.getMessage();

		AssertionService assertionService = new AssertionService();
		Assertion assertion = assertionService.getAssertion(response);

		// Validate
		validationService.validate(request, messageContext, response, assertion, new AuthnRequestWrapper(authnRequest));
	}

	@DisplayName("Test that validator will fail an assertion with the wrong destination")
	@Test
	public void testFailAssertionWithWrongDestination() throws Exception {
		AssertionValidationService validationService = new AssertionValidationService();

		// Mock HttpServletRequest
		HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
		Mockito.when(request.getRequestURL()).thenReturn(new StringBuffer(TestConstants.BAD_SP_ASSERTION_CONSUMER_URL));

		// Create AuthnRequest
		AuthnRequestService authnRequestService = AuthnRequestService.getInstance();
		AuthnRequest authnRequest = authnRequestService.createAuthnRequest(TestConstants.SP_ASSERTION_CONSUMER_URL, false, false, NSISLevel.SUBSTANTIAL);
		String inResponseToId = authnRequest.getID();

		// Create MessageContext, Response and Assertion
		String nameID = "https://data.gov.dk/model/core/eid/person/uuid/37a5a1aa-67ce-4f70-b7c0-b8e678d585f7";
		MessageContext<SAMLObject> messageContext = IdpUtil.createMessageWithAssertion(true, true, true,  nameID, TestConstants.SP_ENTITY_ID, TestConstants.SP_ASSERTION_CONSUMER_URL, inResponseToId);
		Response response = (Response) messageContext.getMessage();

		AssertionService assertionService = new AssertionService();
		Assertion assertion = assertionService.getAssertion(response);


		// Validate, should fail, destination incorrect
		Assertions.assertThrows(ExternalException.class , () -> {
			validationService.validate(request, messageContext, response, assertion, new AuthnRequestWrapper(authnRequest));
		});
	}
	
	@DisplayName("Test that validator will fail an expired assertion")
	@Test
	public void testFailExpiredAssertion() throws Exception {
		AssertionValidationService validationService = new AssertionValidationService();

		// Mock HttpServletRequest
		HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
		Mockito.when(request.getRequestURL()).thenReturn(new StringBuffer(TestConstants.SP_ASSERTION_CONSUMER_URL));

		// Create AuthnRequest
		AuthnRequestService authnRequestService = AuthnRequestService.getInstance();
		AuthnRequest authnRequest = authnRequestService.createAuthnRequest(TestConstants.SP_ASSERTION_CONSUMER_URL, false, false, NSISLevel.SUBSTANTIAL);
		String inResponseToId = authnRequest.getID();

		// Create MessageContext, Response and Assertion
		String nameID = "https://data.gov.dk/model/core/eid/person/uuid/37a5a1aa-67ce-4f70-b7c0-b8e678d585f7";
		MessageContext<SAMLObject> messageContext = IdpUtil.createMessageWithAssertion(true, true, true,  nameID, TestConstants.SP_ENTITY_ID, TestConstants.SP_ASSERTION_CONSUMER_URL, inResponseToId);
		Response response = (Response) messageContext.getMessage();

		AssertionService assertionService = new AssertionService();
		Assertion assertion = assertionService.getAssertion(response);

		// Make assertion seem old
		assertion.setIssueInstant(DateTime.now().minusHours(1));

		// Validate, should fail
		Assertions.assertThrows(AssertionValidationException.class , () -> {
			validationService.validate(request, messageContext, response, assertion, new AuthnRequestWrapper(authnRequest));
		});
	}
	
	@DisplayName("Test that validator will fail a plaintext assertion")
	@Test
	public void testFailPlaintextAssertion() throws Exception {
		AssertionValidationService validationService = new AssertionValidationService();

		// Mock HttpServletRequest
		HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
		Mockito.when(request.getRequestURL()).thenReturn(new StringBuffer(TestConstants.SP_ASSERTION_CONSUMER_URL));

		// Create AuthnRequest
		AuthnRequestService authnRequestService = AuthnRequestService.getInstance();
		AuthnRequest authnRequest = authnRequestService.createAuthnRequest(TestConstants.SP_ASSERTION_CONSUMER_URL, false, false, NSISLevel.SUBSTANTIAL);
		String inResponseToId = authnRequest.getID();

		// Create MessageContext, Response and Assertion
		String nameID = "https://data.gov.dk/model/core/eid/person/uuid/37a5a1aa-67ce-4f70-b7c0-b8e678d585f7";
		MessageContext<SAMLObject> messageContext = IdpUtil.createMessageWithAssertion(false, true, true,  nameID, TestConstants.SP_ENTITY_ID, TestConstants.SP_ASSERTION_CONSUMER_URL, inResponseToId);
		Response response = (Response) messageContext.getMessage();

		AssertionService assertionService = new AssertionService();
		Assertion assertion = assertionService.getAssertion(response);

		// Validate, should fail, encrypted = false
		Assertions.assertThrows(AssertionValidationException.class , () -> {
			validationService.validate(request, messageContext, response, assertion, new AuthnRequestWrapper(authnRequest));
		});
	}
	
	@DisplayName("Test that validator will fail response with > 1 assertions")
	@Test
	public void testFailMultipleAssertions() throws Exception {
		AssertionValidationService validationService = new AssertionValidationService();

		// Mock HttpServletRequest
		HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
		Mockito.when(request.getRequestURL()).thenReturn(new StringBuffer(TestConstants.SP_ASSERTION_CONSUMER_URL));

		// Create AuthnRequest
		AuthnRequestService authnRequestService = AuthnRequestService.getInstance();
		AuthnRequest authnRequest = authnRequestService.createAuthnRequest(TestConstants.SP_ASSERTION_CONSUMER_URL, false, false, NSISLevel.SUBSTANTIAL);
		String inResponseToId = authnRequest.getID();

		// Create MessageContext, Response and EncryptedAssertion
		String nameID = "https://data.gov.dk/model/core/eid/person/uuid/37a5a1aa-67ce-4f70-b7c0-b8e678d585f7";
		MessageContext<SAMLObject> messageContext = IdpUtil.createMessageWithAssertion(true, true, true,  nameID, TestConstants.SP_ENTITY_ID, TestConstants.SP_ASSERTION_CONSUMER_URL, inResponseToId);
		Response response = (Response) messageContext.getMessage();

		AssertionService assertionService = new AssertionService();
		Assertion assertion = assertionService.getAssertion(response);

		// Test with 1 Encrypted & 1 Plaintext
		response.getAssertions().add(SamlHelper.build(Assertion.class));

		Assertions.assertThrows(AssertionValidationException.class , () -> {
			validationService.validate(request, messageContext, response, assertion, new AuthnRequestWrapper(authnRequest));
		});

		// Test with 2 Encrypted
		response.getAssertions().clear();

		EncryptedAssertion encryptedAssertion = response.getEncryptedAssertions().get(0);
		EncryptedAssertionMarshaller marshaller = new EncryptedAssertionMarshaller();
		EncryptedAssertionUnmarshaller unmarshaller = new EncryptedAssertionUnmarshaller();
		EncryptedAssertion copy = (EncryptedAssertion) unmarshaller.unmarshall(marshaller.marshall(encryptedAssertion));
		response.getEncryptedAssertions().add(copy);

		Assertions.assertThrows(AssertionValidationException.class , () -> {
			validationService.validate(request, messageContext, response, assertion, new AuthnRequestWrapper(authnRequest));
		});

		// Test with 2 Plaintext
		response.getEncryptedAssertions().clear();
		response.getAssertions().add(SamlHelper.build(Assertion.class));
		response.getAssertions().add(SamlHelper.build(Assertion.class));

		Assertions.assertThrows(AssertionValidationException.class , () -> {
			validationService.validate(request, messageContext, response, assertion, new AuthnRequestWrapper(authnRequest));
		});
	}
	
	@DisplayName("Test that validator will fail an assertion issued by an untrusted IdP")
	@Test
	public void testFailWrongIssuer() throws Exception {
		AssertionValidationService validationService = new AssertionValidationService();

		// Mock HttpServletRequest
		HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
		Mockito.when(request.getRequestURL()).thenReturn(new StringBuffer(TestConstants.SP_ASSERTION_CONSUMER_URL));

		// Create AuthnRequest
		AuthnRequestService authnRequestService = AuthnRequestService.getInstance();
		AuthnRequest authnRequest = authnRequestService.createAuthnRequest(TestConstants.SP_ASSERTION_CONSUMER_URL, false, false, NSISLevel.SUBSTANTIAL);
		String inResponseToId = authnRequest.getID();

		// Create MessageContext, Response and Assertion
		String nameID = "https://data.gov.dk/model/core/eid/person/uuid/37a5a1aa-67ce-4f70-b7c0-b8e678d585f7";
		MessageContext<SAMLObject> messageContext = IdpUtil.createMessageWithAssertion(true, true, true,  nameID, TestConstants.SP_ENTITY_ID, TestConstants.SP_ASSERTION_CONSUMER_URL, inResponseToId);
		Response response = (Response) messageContext.getMessage();

		AssertionService assertionService = new AssertionService();
		Assertion assertion = assertionService.getAssertion(response);

		// Substitute good issuer for bad one for test
		Issuer badIssuer = SamlHelper.build(Issuer.class);
		badIssuer.setFormat(Issuer.ENTITY);
		badIssuer.setValue("NotARealIssuer");
		assertion.setIssuer(badIssuer);

		// Validate, should fail "Issuer does not match IdP EntityID from metadata"
		Assertions.assertThrows(AssertionValidationException.class , () -> {
			validationService.validate(request, messageContext, response, assertion, new AuthnRequestWrapper(authnRequest));
		});
	}
	
	@DisplayName("Test that validator will fail an assertion with a bad signature")
	@Test
	public void testFailBadSignature() throws Exception {
		AssertionValidationService validationService = new AssertionValidationService();

		// Mock HttpServletRequest
		HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
		Mockito.when(request.getRequestURL()).thenReturn(new StringBuffer(TestConstants.SP_ASSERTION_CONSUMER_URL));

		// Create AuthnRequest
		AuthnRequestService authnRequestService = AuthnRequestService.getInstance();
		AuthnRequest authnRequest = authnRequestService.createAuthnRequest(TestConstants.SP_ASSERTION_CONSUMER_URL, false, false, NSISLevel.SUBSTANTIAL);
		String inResponseToId = authnRequest.getID();

		// Create MessageContext, Response and Assertion
		String nameID = "https://data.gov.dk/model/core/eid/person/uuid/37a5a1aa-67ce-4f70-b7c0-b8e678d585f7";
		MessageContext<SAMLObject> messageContext = IdpUtil.createMessageWithAssertion(true, true, false,  nameID, TestConstants.SP_ENTITY_ID, TestConstants.SP_ASSERTION_CONSUMER_URL, inResponseToId);
		Response response = (Response) messageContext.getMessage();

		AssertionService assertionService = new AssertionService();
		Assertion assertion = assertionService.getAssertion(response);

		// Validate, should fail "Could not validate assertion signature"
		Assertions.assertThrows(AssertionValidationException.class , () -> {
			validationService.validate(request, messageContext, response, assertion, new AuthnRequestWrapper(authnRequest));
		});
	}
	
	@DisplayName("Test that validator will fail an assertion with the wrong audience")
	@Test
	public void testFailWrongAudience() throws Exception {
		AssertionValidationService validationService = new AssertionValidationService();

		// Mock HttpServletRequest
		HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
		Mockito.when(request.getRequestURL()).thenReturn(new StringBuffer(TestConstants.SP_ASSERTION_CONSUMER_URL));

		// Create AuthnRequest
		AuthnRequestService authnRequestService = AuthnRequestService.getInstance();
		AuthnRequest authnRequest = authnRequestService.createAuthnRequest(TestConstants.SP_ASSERTION_CONSUMER_URL, false, false, NSISLevel.SUBSTANTIAL);
		String inResponseToId = authnRequest.getID();

		// Create MessageContext, Response and Assertion
		String nameID = "https://data.gov.dk/model/core/eid/person/uuid/37a5a1aa-67ce-4f70-b7c0-b8e678d585f7";
		MessageContext<SAMLObject> messageContext = IdpUtil.createMessageWithAssertion(true, true, true,  nameID, TestConstants.SP_ENTITY_ID, TestConstants.SP_ASSERTION_CONSUMER_URL, inResponseToId);
		Response response = (Response) messageContext.getMessage();

		AssertionService assertionService = new AssertionService();
		Assertion assertion = assertionService.getAssertion(response);

		// Substitute good AudienceRestriction for bad one for test
		AudienceRestriction audienceRestriction = SamlHelper.build(AudienceRestriction.class);
		Audience audience = SamlHelper.build(Audience.class);
		audience.setAudienceURI("NotTheCorrectRecipient");
		audienceRestriction.getAudiences().add(audience);
		List<AudienceRestriction> restrictions = assertion.getConditions().getAudienceRestrictions();
		restrictions.clear();
		restrictions.add(audienceRestriction);


		// Validate, should fail "The assertion MUST contain an AudienceRestriction including the ServiceProvider's unique identifier as an Audience"
		Assertions.assertThrows(AssertionValidationException.class , () -> {
			validationService.validate(request, messageContext, response, assertion, new AuthnRequestWrapper(authnRequest));
		});
	}
	
	@DisplayName("Test that validator will fail an assertion if the subject/NameID is malformed")
	@Test
	public void testFailWrongSubject() throws Exception {
		AssertionValidationService validationService = new AssertionValidationService();

		// Mock HttpServletRequest
		HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
		Mockito.when(request.getRequestURL()).thenReturn(new StringBuffer(TestConstants.SP_ASSERTION_CONSUMER_URL));

		// Create AuthnRequest
		AuthnRequestService authnRequestService = AuthnRequestService.getInstance();
		AuthnRequest authnRequest = authnRequestService.createAuthnRequest(TestConstants.SP_ASSERTION_CONSUMER_URL, false, false, NSISLevel.SUBSTANTIAL);
		String inResponseToId = authnRequest.getID();

		// Create MessageContext, Response and Assertion
		String incorrectNameID = "https://data.gov.dk/model/core/eid/person/uuid/NotAUuidXyzAbcD";
		MessageContext<SAMLObject> messageContext = IdpUtil.createMessageWithAssertion(true, true, true,  incorrectNameID, TestConstants.SP_ENTITY_ID, TestConstants.SP_ASSERTION_CONSUMER_URL, inResponseToId);
		Response response = (Response) messageContext.getMessage();

		AssertionService assertionService = new AssertionService();
		Assertion assertion = assertionService.getAssertion(response);

		// Validate, should fail "Subject NameID should be based on a UUID"
		Assertions.assertThrows(AssertionValidationException.class , () -> {
			validationService.validate(request, messageContext, response, assertion, new AuthnRequestWrapper(authnRequest));
		});
	}
}
