package dk.gov.oio.saml.service.validation;

import dk.gov.oio.saml.model.NSISLevel;
import dk.gov.oio.saml.service.AssertionService;
import dk.gov.oio.saml.service.AuthnRequestService;
import dk.gov.oio.saml.service.BaseServiceTest;
import dk.gov.oio.saml.service.IdPMetadataService;
import dk.gov.oio.saml.service.OIOSAML3Service;
import dk.gov.oio.saml.session.AuthnRequestWrapper;
import dk.gov.oio.saml.util.ExternalException;
import dk.gov.oio.saml.util.IdpUtil;
import dk.gov.oio.saml.util.SamlHelper;
import dk.gov.oio.saml.util.TestConstants;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.UUID;
import javax.servlet.http.HttpServletRequest;
import org.joda.time.DateTime;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.assertion.AssertionValidationException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.impl.EncryptedAssertionMarshaller;
import org.opensaml.saml.saml2.core.impl.EncryptedAssertionUnmarshaller;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

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
        AuthnRequest authnRequest = getAuthnRequest(authnRequestService);
        String inResponseToId = authnRequest.getID();

        // Create MessageContext, Response and Assertion
        String nameID = "https://data.gov.dk/model/core/eid/person/uuid/37a5a1aa-67ce-4f70-b7c0-b8e678d585f7";
        MessageContext<SAMLObject> messageContext = IdpUtil.createMessageWithAssertion(true, true, true, nameID, TestConstants.SP_ENTITY_ID, TestConstants.SP_ASSERTION_CONSUMER_URL, inResponseToId);
        Response response = (Response) messageContext.getMessage();

        AssertionService assertionService = new AssertionService();
        Assertion assertion = assertionService.getAssertion(response);

        // Validate
        validationService.validate(request, messageContext, response, assertion, new AuthnRequestWrapper(authnRequest, NSISLevel.SUBSTANTIAL, ""));
    }

    @DisplayName("Test that validator will pass an assertion issued under a newer OIOSAML profile version")
    @Test
    public void testValidateAssertionWithNewerSpecVersion() throws Exception {
        AssertionValidationService validationService = new AssertionValidationService();

        // Mock HttpServletRequest
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getRequestURL()).thenReturn(new StringBuffer(TestConstants.SP_ASSERTION_CONSUMER_URL));

        // Create AuthnRequest
        AuthnRequestService authnRequestService = AuthnRequestService.getInstance();
        AuthnRequest authnRequest = getAuthnRequest(authnRequestService);
        String inResponseToId = authnRequest.getID();

        // Create MessageContext, Response and Assertion, with the specVersion value used by OIOSAML 4.0.0
        String nameID = "https://data.gov.dk/model/core/eid/person/uuid/37a5a1aa-67ce-4f70-b7c0-b8e678d585f7";
        MessageContext<SAMLObject> messageContext = IdpUtil.createMessageWithAssertion(true, true, true, nameID, TestConstants.SP_ENTITY_ID, TestConstants.SP_ASSERTION_CONSUMER_URL, inResponseToId, TestConstants.SPEC_VERSION_OIOSAML_40);
        Response response = (Response) messageContext.getMessage();

        AssertionService assertionService = new AssertionService();
        Assertion assertion = assertionService.getAssertion(response);

        // Validate
        validationService.validate(request, messageContext, response, assertion, new AuthnRequestWrapper(authnRequest, NSISLevel.SUBSTANTIAL, ""));
    }

    @DisplayName("Test that validator will fail an assertion without a specVersion attribute")
    @Test
    public void testFailAssertionWithoutSpecVersion() throws Exception {
        AssertionValidationService validationService = new AssertionValidationService();

        // Mock HttpServletRequest
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getRequestURL()).thenReturn(new StringBuffer(TestConstants.SP_ASSERTION_CONSUMER_URL));

        // Create AuthnRequest
        AuthnRequestService authnRequestService = AuthnRequestService.getInstance();
        AuthnRequest authnRequest = getAuthnRequest(authnRequestService);
        String inResponseToId = authnRequest.getID();

        // Create MessageContext, Response and Assertion, without the mandatory specVersion attribute
        String nameID = "https://data.gov.dk/model/core/eid/person/uuid/37a5a1aa-67ce-4f70-b7c0-b8e678d585f7";
        MessageContext<SAMLObject> messageContext = IdpUtil.createMessageWithAssertion(true, true, true, nameID, TestConstants.SP_ENTITY_ID, TestConstants.SP_ASSERTION_CONSUMER_URL, inResponseToId, null);
        Response response = (Response) messageContext.getMessage();

        AssertionService assertionService = new AssertionService();
        Assertion assertion = assertionService.getAssertion(response);

        // Validate, should fail, specVersion is mandatory
        Assertions.assertThrows(AssertionValidationException.class, () -> {
            validationService.validate(request, messageContext, response, assertion, new AuthnRequestWrapper(authnRequest, NSISLevel.SUBSTANTIAL, ""));
        });
    }

    @DisplayName("Test that validator accepts a signature made with any of the signing certificates in metadata")
    @Test
    public void testValidateAssertionSignedWithSecondCertificateInMetadata() throws Exception {
        AssertionValidationService validationService = new AssertionValidationService();

        // Metadata where the certificate actually used for signing is preceded by another one, as it is
        // while the IdP rotates its signing key
        String otherCertificate = IdpUtil.getIdpCertificateBase64(false);
        String metadata = TestConstants.IDP_METADATA.replaceFirst("<md:KeyDescriptor use=\"signing\">",
                "<md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>"
                        + otherCertificate + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:KeyDescriptor use=\"signing\">");

        String originalMetadataFile = OIOSAML3Service.getConfig().getIdpMetadataFile();
        OIOSAML3Service.getConfig().setIdpMetadataFile(TestConstants.writeIdpMetadataFile(metadata));
        IdPMetadataService.getInstance().clear(TestConstants.IDP_ENTITY_ID);

        try {
            // Mock HttpServletRequest
            HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
            Mockito.when(request.getRequestURL()).thenReturn(new StringBuffer(TestConstants.SP_ASSERTION_CONSUMER_URL));

            // Create AuthnRequest
            AuthnRequestService authnRequestService = AuthnRequestService.getInstance();
            AuthnRequest authnRequest = getAuthnRequest(authnRequestService);
            String inResponseToId = authnRequest.getID();

            // Create MessageContext, Response and Assertion
            String nameID = "https://data.gov.dk/model/core/eid/person/uuid/37a5a1aa-67ce-4f70-b7c0-b8e678d585f7";
            MessageContext<SAMLObject> messageContext = IdpUtil.createMessageWithAssertion(true, true, true, nameID, TestConstants.SP_ENTITY_ID, TestConstants.SP_ASSERTION_CONSUMER_URL, inResponseToId);
            Response response = (Response) messageContext.getMessage();

            Assertion assertion = new AssertionService().getAssertion(response);

            // Validate
            validationService.validate(request, messageContext, response, assertion, new AuthnRequestWrapper(authnRequest, NSISLevel.SUBSTANTIAL, ""));
        }
        finally {
            OIOSAML3Service.getConfig().setIdpMetadataFile(originalMetadataFile);
            IdPMetadataService.getInstance().clear(TestConstants.IDP_ENTITY_ID);
        }
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
        AuthnRequest authnRequest = getAuthnRequest(authnRequestService);
        String inResponseToId = authnRequest.getID();

        // Create MessageContext, Response and Assertion
        String nameID = "https://data.gov.dk/model/core/eid/person/uuid/37a5a1aa-67ce-4f70-b7c0-b8e678d585f7";
        MessageContext<SAMLObject> messageContext = IdpUtil.createMessageWithAssertion(true, true, true,  nameID, TestConstants.SP_ENTITY_ID, TestConstants.SP_ASSERTION_CONSUMER_URL, inResponseToId);
        Response response = (Response) messageContext.getMessage();

        AssertionService assertionService = new AssertionService();
        Assertion assertion = assertionService.getAssertion(response);


        // Validate, should fail, destination incorrect
        Assertions.assertThrows(ExternalException.class , () -> {
            validationService.validate(request, messageContext, response, assertion, new AuthnRequestWrapper(authnRequest, NSISLevel.SUBSTANTIAL, ""));
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
        AuthnRequest authnRequest = getAuthnRequest(authnRequestService);
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
            validationService.validate(request, messageContext, response, assertion, new AuthnRequestWrapper(authnRequest, NSISLevel.SUBSTANTIAL, ""));
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
        AuthnRequest authnRequest = getAuthnRequest(authnRequestService);
        String inResponseToId = authnRequest.getID();

        // Create MessageContext, Response and Assertion
        String nameID = "https://data.gov.dk/model/core/eid/person/uuid/37a5a1aa-67ce-4f70-b7c0-b8e678d585f7";
        MessageContext<SAMLObject> messageContext = IdpUtil.createMessageWithAssertion(false, true, true,  nameID, TestConstants.SP_ENTITY_ID, TestConstants.SP_ASSERTION_CONSUMER_URL, inResponseToId);
        Response response = (Response) messageContext.getMessage();

        AssertionService assertionService = new AssertionService();
        Assertion assertion = assertionService.getAssertion(response);

        // Validate, should fail, encrypted = false
        Assertions.assertThrows(AssertionValidationException.class , () -> {
            validationService.validate(request, messageContext, response, assertion, new AuthnRequestWrapper(authnRequest, NSISLevel.SUBSTANTIAL, ""));
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
        AuthnRequest authnRequest = getAuthnRequest(authnRequestService);
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
            validationService.validate(request, messageContext, response, assertion, new AuthnRequestWrapper(authnRequest, NSISLevel.SUBSTANTIAL, ""));
        });

        // Test with 2 Encrypted
        response.getAssertions().clear();

        EncryptedAssertion encryptedAssertion = response.getEncryptedAssertions().get(0);
        EncryptedAssertionMarshaller marshaller = new EncryptedAssertionMarshaller();
        EncryptedAssertionUnmarshaller unmarshaller = new EncryptedAssertionUnmarshaller();
        EncryptedAssertion copy = (EncryptedAssertion) unmarshaller.unmarshall(marshaller.marshall(encryptedAssertion));
        response.getEncryptedAssertions().add(copy);

        Assertions.assertThrows(AssertionValidationException.class , () -> {
            validationService.validate(request, messageContext, response, assertion, new AuthnRequestWrapper(authnRequest, NSISLevel.SUBSTANTIAL, ""));
        });

        // Test with 2 Plaintext
        response.getEncryptedAssertions().clear();
        response.getAssertions().add(SamlHelper.build(Assertion.class));
        response.getAssertions().add(SamlHelper.build(Assertion.class));

        Assertions.assertThrows(AssertionValidationException.class , () -> {
            validationService.validate(request, messageContext, response, assertion, new AuthnRequestWrapper(authnRequest, NSISLevel.SUBSTANTIAL, ""));
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
        AuthnRequest authnRequest = getAuthnRequest(authnRequestService);
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
            validationService.validate(request, messageContext, response, assertion, new AuthnRequestWrapper(authnRequest, NSISLevel.SUBSTANTIAL, ""));
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
        AuthnRequest authnRequest = getAuthnRequest(authnRequestService);
        String inResponseToId = authnRequest.getID();

        // Create MessageContext, Response and Assertion
        String nameID = "https://data.gov.dk/model/core/eid/person/uuid/37a5a1aa-67ce-4f70-b7c0-b8e678d585f7";
        MessageContext<SAMLObject> messageContext = IdpUtil.createMessageWithAssertion(true, true, false,  nameID, TestConstants.SP_ENTITY_ID, TestConstants.SP_ASSERTION_CONSUMER_URL, inResponseToId);
        Response response = (Response) messageContext.getMessage();

        AssertionService assertionService = new AssertionService();
        Assertion assertion = assertionService.getAssertion(response);

        // Validate, should fail "Could not validate assertion signature"
        Assertions.assertThrows(AssertionValidationException.class , () -> {
            validationService.validate(request, messageContext, response, assertion, new AuthnRequestWrapper(authnRequest, NSISLevel.SUBSTANTIAL, ""));
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
        AuthnRequest authnRequest = getAuthnRequest(authnRequestService);
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
            validationService.validate(request, messageContext, response, assertion, new AuthnRequestWrapper(authnRequest, NSISLevel.SUBSTANTIAL, ""));
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
        AuthnRequest authnRequest = getAuthnRequest(authnRequestService);
        String inResponseToId = authnRequest.getID();

        // Create MessageContext, Response and Assertion
        String incorrectNameID = "https://data.gov.dk/model/core/eid/person/uuid/NotAUuidXyzAbcD";
        MessageContext<SAMLObject> messageContext = IdpUtil.createMessageWithAssertion(true, true, true,  incorrectNameID, TestConstants.SP_ENTITY_ID, TestConstants.SP_ASSERTION_CONSUMER_URL, inResponseToId);
        Response response = (Response) messageContext.getMessage();

        AssertionService assertionService = new AssertionService();
        Assertion assertion = assertionService.getAssertion(response);

        // Validate, should fail "Subject NameID should be based on a UUID"
        Assertions.assertThrows(AssertionValidationException.class , () -> {
            validationService.validate(request, messageContext, response, assertion, new AuthnRequestWrapper(authnRequest, NSISLevel.SUBSTANTIAL, ""));
        });
    }

    @DisplayName("Test that validator will fail an assertion whose signature reference resolves to another element")
    @Test
    public void testFailSignatureNotBoundToAssertion() throws Exception {
        AssertionValidationService validationService = new AssertionValidationService();

        // Mock HttpServletRequest
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getRequestURL()).thenReturn(new StringBuffer(TestConstants.SP_ASSERTION_CONSUMER_URL));

        // Create AuthnRequest
        AuthnRequestService authnRequestService = AuthnRequestService.getInstance();
        AuthnRequest authnRequest = getAuthnRequest(authnRequestService);
        String inResponseToId = authnRequest.getID();

        // Create MessageContext, Response and a correctly signed Assertion
        String nameID = "https://data.gov.dk/model/core/eid/person/uuid/37a5a1aa-67ce-4f70-b7c0-b8e678d585f7";
        MessageContext<SAMLObject> messageContext = IdpUtil.createMessageWithAssertion(true, true, true, nameID, TestConstants.SP_ENTITY_ID, TestConstants.SP_ASSERTION_CONSUMER_URL, inResponseToId);
        Response response = (Response) messageContext.getMessage();

        Assertion signedAssertion = new AssertionService().getAssertion(response);

        // Assertion with a different ID and subject than the one the signature reference resolves to
        String substituteNameID = "https://data.gov.dk/model/core/eid/person/uuid/11111111-2222-3333-4444-555555555555";
        Assertion unboundAssertion = buildAssertionWithUnboundSignature(signedAssertion, "_copy" + UUID.randomUUID().toString().replace("-", ""), substituteNameID);

        // Only interesting while the signature itself still verifies, otherwise the test would pass for the
        // wrong reason
        List<X509Certificate> idpCertificates = IdPMetadataService.getInstance().getIdPMetadata().getValidX509Certificates(UsageType.SIGNING);
        SignatureValidator.validate(unboundAssertion.getSignature(), new BasicX509Credential(idpCertificates.get(0)));

        // Validate, should fail because the signature is not bound to the assertion being consumed
        AssertionValidationException exception = Assertions.assertThrows(AssertionValidationException.class, () -> {
            validationService.validate(request, messageContext, response, unboundAssertion, new AuthnRequestWrapper(authnRequest, NSISLevel.SUBSTANTIAL, ""));
        });
        Assertions.assertTrue(exception.getMessage().toLowerCase().contains("signature"), "Expected the signature validation to reject the assertion, but failed with: " + exception.getMessage());
    }

    @DisplayName("Test that validator will fail an assertion whose signature reference is ambiguous")
    @Test
    public void testFailSignatureNotBoundToAssertionWithReusedId() throws Exception {
        AssertionValidationService validationService = new AssertionValidationService();

        // Mock HttpServletRequest
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getRequestURL()).thenReturn(new StringBuffer(TestConstants.SP_ASSERTION_CONSUMER_URL));

        // Create AuthnRequest
        AuthnRequestService authnRequestService = AuthnRequestService.getInstance();
        AuthnRequest authnRequest = getAuthnRequest(authnRequestService);
        String inResponseToId = authnRequest.getID();

        // Create MessageContext, Response and a correctly signed Assertion
        String nameID = "https://data.gov.dk/model/core/eid/person/uuid/37a5a1aa-67ce-4f70-b7c0-b8e678d585f7";
        MessageContext<SAMLObject> messageContext = IdpUtil.createMessageWithAssertion(true, true, true, nameID, TestConstants.SP_ENTITY_ID, TestConstants.SP_ASSERTION_CONSUMER_URL, inResponseToId);
        Response response = (Response) messageContext.getMessage();

        Assertion signedAssertion = new AssertionService().getAssertion(response);

        // Same document shape, but the consumed assertion keeps the ID of the element the reference resolves
        // to, so comparing the reference URI to the ID of its parent element is not enough to tell them apart
        String substituteNameID = "https://data.gov.dk/model/core/eid/person/uuid/11111111-2222-3333-4444-555555555555";
        Assertion unboundAssertion = buildAssertionWithUnboundSignature(signedAssertion, signedAssertion.getID(), substituteNameID);

        // Validate, should fail because the reference does not resolve to the assertion being consumed
        AssertionValidationException exception = Assertions.assertThrows(AssertionValidationException.class, () -> {
            validationService.validate(request, messageContext, response, unboundAssertion, new AuthnRequestWrapper(authnRequest, NSISLevel.SUBSTANTIAL, ""));
        });
        Assertions.assertTrue(exception.getMessage().toLowerCase().contains("signature"), "Expected the signature validation to reject the assertion, but failed with: " + exception.getMessage());
    }

    /**
     * Build an assertion carrying a signature that verifies but is not bound to it: a copy of the signed
     * assertion with the given ID and subject NameID, holding the signature, while the element the signature
     * reference resolves to sits further down the same document.
     */
    private static Assertion buildAssertionWithUnboundSignature(Assertion signedAssertion, String id, String nameID) throws Exception {
        Element signedElement = signedAssertion.getDOM();
        Document document = signedElement.getOwnerDocument();

        Element copy = (Element) signedElement.cloneNode(true);
        copy.setAttributeNS(null, "ID", id);
        ((Element) copy.getElementsByTagNameNS(SAMLConstants.SAML20_NS, "NameID").item(0)).setTextContent(nameID);

        // Only the copy keeps the signature, so the referenced element still digests to the signed value
        Element signature = (Element) signedElement.getElementsByTagNameNS(SignatureConstants.XMLSIG_NS, "Signature").item(0);
        signedElement.removeChild(signature);

        // The copy becomes the document element and the referenced element is nested inside it
        document.removeChild(signedElement);
        document.appendChild(copy);

        Element advice = document.createElementNS(SAMLConstants.SAML20_NS, "saml2:Advice");
        copy.appendChild(advice);
        advice.appendChild(signedElement);

        return (Assertion) XMLObjectProviderRegistrySupport.getUnmarshallerFactory().getUnmarshaller(copy).unmarshall(copy);
    }

    private static AuthnRequest getAuthnRequest(AuthnRequestService authnRequestService) throws InitializationException {
        AuthnRequest authnRequest = authnRequestService.createAuthnRequest( TestConstants.SP_ASSERTION_CONSUMER_URL, false, false, NSISLevel.SUBSTANTIAL, null);
        return authnRequest;
    }
}
