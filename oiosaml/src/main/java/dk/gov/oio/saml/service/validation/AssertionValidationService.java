package dk.gov.oio.saml.service.validation;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.joda.time.DateTime;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.assertion.AssertionValidationException;
import org.opensaml.saml.common.binding.security.impl.MessageLifetimeSecurityHandler;
import org.opensaml.saml.common.binding.security.impl.ReceivedEndpointSecurityHandler;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;

import dk.gov.oio.saml.config.Configuration;
import dk.gov.oio.saml.model.NSISLevel;
import dk.gov.oio.saml.service.IdPMetadataService;
import dk.gov.oio.saml.service.OIOSAML3Service;
import dk.gov.oio.saml.session.AuthnRequestWrapper;
import dk.gov.oio.saml.util.Constants;
import dk.gov.oio.saml.util.ExternalException;
import dk.gov.oio.saml.util.InternalException;
import dk.gov.oio.saml.util.SamlHelper;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

public class AssertionValidationService {
    private static final Logger log = LoggerFactory.getLogger(AssertionValidationService.class);

    public void validate(HttpServletRequest httpServletRequest, MessageContext<SAMLObject> messageContext, Response response, Assertion assertion, AuthnRequestWrapper authnRequest) throws AssertionValidationException, InternalException, ExternalException {
        validateDestination(httpServletRequest, messageContext);
        validateLifetime(messageContext, response, assertion);
        validateResponse(response, authnRequest);
        validateAssertion(assertion, authnRequest);
    }

    @SuppressWarnings("unchecked")
    private void validateDestination(HttpServletRequest httpServletRequest, MessageContext<SAMLObject> messageContext) throws InternalException, ExternalException {
        ReceivedEndpointSecurityHandler endpointSecurityHandler = null;
        try {
            endpointSecurityHandler = new ReceivedEndpointSecurityHandler();
            endpointSecurityHandler.setHttpServletRequest(httpServletRequest);
            endpointSecurityHandler.initialize();
            endpointSecurityHandler.invoke(messageContext);
        }
        catch (ComponentInitializationException e) {
            throw new InternalException("Could not initialize ReceivedEndpointSecurityHandler", e);
        }
        catch (MessageHandlerException e) {
            throw new ExternalException("Destination incorrect", e);
        }
        finally {
            if (endpointSecurityHandler != null && endpointSecurityHandler.isInitialized() && !endpointSecurityHandler.isDestroyed()) {
                endpointSecurityHandler.destroy();
            }
        }
    }

    @SuppressWarnings("unchecked")
    private void validateLifetime(MessageContext<SAMLObject> messageContext, Response response, Assertion assertion) throws InternalException, AssertionValidationException {
        int clockSkew = OIOSAML3Service.getConfig().getClockSkew();

        MessageLifetimeSecurityHandler lifetimeHandler = null;
        try {
            lifetimeHandler = new MessageLifetimeSecurityHandler();
            lifetimeHandler.setClockSkew(1000L * 60 * clockSkew);
            lifetimeHandler.initialize();
            lifetimeHandler.invoke(messageContext);
        } catch (ComponentInitializationException e) {
            throw new InternalException("Could not initialize MessageLifetimeSecurityHandler", e);
        } catch (MessageHandlerException e) {
            throw new AssertionValidationException("Message lifetime incorrect", e);
        } finally {
            if (lifetimeHandler != null && lifetimeHandler.isInitialized() && !lifetimeHandler.isDestroyed()) {
                lifetimeHandler.destroy();
            }
        }

        //Check Response Issue instant
        DateTime responseIssueInstant = response.getIssueInstant();
        if (responseIssueInstant.isBefore(DateTime.now().minusMinutes(clockSkew))) {
            throw new AssertionValidationException("Response Lifetime incorrect");
        }

        //Check Assertion Issue instant
        DateTime assertionIssueInstant = assertion.getIssueInstant();
        if (assertionIssueInstant.isBefore(DateTime.now().minusMinutes(clockSkew))) {
            throw new AssertionValidationException("Assertion Lifetime incorrect");
        }

        // Check conditions
        Conditions conditions = assertion.getConditions();
        if (conditions != null) {
            if (conditions.getNotOnOrAfter() != null) {
                if (!DateTime.now().minusMinutes(clockSkew).isBefore(conditions.getNotOnOrAfter())) {
                    throw new AssertionValidationException("Assertion conditions notOnOrAfter expired");
                }
            }

            if (conditions.getNotBefore() != null) {
                if (!DateTime.now().plusMinutes(clockSkew).isAfter(conditions.getNotBefore())) {
                    throw new AssertionValidationException("Assertion conditions notBefore not reached yet");
                }
            }
        }
    }

    private void validateResponse(Response response, AuthnRequestWrapper authnRequest) throws AssertionValidationException {
        validateStatus(response);
        validateInResponseTo(response, authnRequest);

        // specific OIOSAML 3.0 validation is configurable, and can be disabled
        Configuration config = OIOSAML3Service.getConfig();
        if (config.isValidationEnabled()) {
            // Successful responses SHOULD NOT be directly signed.
            if (response.isSigned()) {
                log.warn("Successful responses SHOULD NOT be directly signed.");
            }
    
            // Successful responses MUST contain exactly one encrypted SAML Assertion
            List<Assertion> assertions = response.getAssertions();
            if (assertions != null && assertions.size() != 0) {
                throw new AssertionValidationException("MUST contain exactly one SAML Assertion, which should be encrypted");
            }
    
            // Assertions transferred via the user agent MUST be encrypted and transmitted via a EncryptedAssertion element
            List<EncryptedAssertion> encryptedAssertions = response.getEncryptedAssertions();
            if (encryptedAssertions == null || encryptedAssertions.size() != 1) {
                throw new AssertionValidationException("MUST contain exactly one SAML Assertion");
            }
        }
    }

    private void validateAssertion(Assertion assertion, AuthnRequestWrapper authnRequest) throws AssertionValidationException, ExternalException, InternalException {
        validateSignature(assertion);

        validateIssuer(assertion);

        // specific OIOSAML 3.0 validation is configurable, and can be disabled
        Configuration config = OIOSAML3Service.getConfig();
        if (config.isValidationEnabled()) {
            validateSubject(assertion, authnRequest);
        }

        validateAudienceRestriction(assertion);

        // The assertion MUST contain exactly one AuthnStatement sub-element
        List<AuthnStatement> authnStatements = assertion.getAuthnStatements();
        if (authnStatements == null || authnStatements.size() != 1) {
            throw new AssertionValidationException("Assertions MUST contain exactly one AuthnStatement sub-element");
        }

        // MUST contain exactly one AttributeStatement sub-element
        List<AttributeStatement> attributeStatements = assertion.getAttributeStatements();
        if (attributeStatements == null || attributeStatements.size() != 1) {
            throw new AssertionValidationException("Assertions MUST contain exactly one AttributeStatement sub-element");
        }

        Map<String, String> attributeValues = SamlHelper.extractAttributeValues(attributeStatements.get(0));
        if (!config.isValidationEnabled()) {
            return;
        }

        // The AttributeStatement sub-element MUST conform to one of the attribute profiles for natural persons or professionals
        String nameIDValue = assertion.getSubject().getNameID().getValue();
        validateAttributeStatement(attributeValues, nameIDValue.startsWith("https://data.gov.dk/model/core/eid/professional"));
        validateAssurance(attributeValues, authnRequest);

        // The Assertion within the response MUST be directly signed
        if (!assertion.isSigned()) {
            throw new AssertionValidationException("The Assertion within the response MUST be directly signed");
        }
    }

    private void validateAttributeStatement(Map<String, String> attributes, boolean isProfessional) throws AssertionValidationException {
        // SpecVer
        String specVersion = attributes.get(Constants.SPEC_VER);
        if (!Constants.SPEC_VER_VAL.equals(specVersion)) {
            throw new AssertionValidationException("specVersion Was: " + specVersion + " Expected: " + Constants.SPEC_VER_VAL);
        }

        // Professional
        if (isProfessional) {
            String cvr = attributes.get(Constants.CVR_NUMBER);
            if (cvr == null || !cvr.matches("^\\d{8}$")) {
                throw new AssertionValidationException("CVR should be present and should be an 8-digit number");
            }

            String orgName = attributes.get(Constants.ORGANIZATION_NAME);
            if (orgName == null || orgName.isEmpty()) {
                throw new AssertionValidationException("Organization Name should be present");
            }
        }

    }

    private void validateAssurance(Map<String, String> attributes, AuthnRequestWrapper authnRequest) throws AssertionValidationException {
        Configuration configuration = OIOSAML3Service.getConfig();
        String assuranceLevel = attributes.get(Constants.ASSURANCE_LEVEL);
        if(authnRequest.getRequestedNsisLevel() == NSISLevel.NONE && assuranceLevel != null) {
            log.info("Assurance level of {} received. Accepting, requested NSIS LoA was NONE", assuranceLevel);
            return;
        }

        if(!configuration.isAssuranceLevelAllowed() && assuranceLevel != null) {
            throw new AssertionValidationException("NSIS LoA required, but received AssuranceLevel");
        }

        if(configuration.isAssuranceLevelSufficient(assuranceLevel)) {
            log.info("Assurance level of {} received instead of NSIS LoA. Accepted because of configuration", assuranceLevel);
            return;
        }

        // LOA
        String loa = attributes.get(Constants.LOA);
        if (loa == null) {
            throw new AssertionValidationException("Must Contain Level of assurance");
        }

        // Attribute value is not URL, but only name
        NSISLevel actualLevel = NSISLevel.getNSISLevelFromAttributeValue(loa, null);
        if(actualLevel == null) {
            throw new AssertionValidationException("Level of assurance was not correct value. Was: " + loa);
        }

        // SPs MUST check the specified [NSIS]level of assurance regardless of any LoA was set in the request
        NSISLevel requestedLevel = NSISLevel.NONE;
        for (String authnContextClassRef : authnRequest.getAuthnContextClassRefValues()) {
            NSISLevel nsisLevelFromLOA = NSISLevel.getNSISLevelFromUrl(authnContextClassRef, null);

            if (nsisLevelFromLOA != null) {
                requestedLevel = nsisLevelFromLOA;
            }
        }

        if (requestedLevel.isGreater(actualLevel)) {
            throw new AssertionValidationException("Assertion NSIS Level not sufficient. Was: '" + actualLevel + "' Expected: '" + requestedLevel + "'");
        }
    }

    private void validateStatus(Response response) throws AssertionValidationException {
        if (response.getStatus() == null || response.getStatus().getStatusCode() == null) {
            throw new AssertionValidationException("Response status or Response status statuscode was null");
        }

        if (!StatusCode.SUCCESS.equals(response.getStatus().getStatusCode().getValue())) {
            throw new AssertionValidationException("Response status code is not Success. Expected: " + StatusCode.SUCCESS + " Was: " + response.getStatus().getStatusCode().getValue());
        }
    }

    private void validateInResponseTo(Response response, AuthnRequestWrapper authnRequest) throws AssertionValidationException {
        if (!java.util.Objects.equals(authnRequest.getId(), response.getInResponseTo())) {
            throw new AssertionValidationException("InResponseTo does not match AuthnRequest ID. Expected: " + authnRequest.getId() + " Was: " + response.getInResponseTo());
        }
    }

    private void validateSignature(Assertion assertion) throws ExternalException, InternalException, AssertionValidationException {
        // Get Signing credential
        X509Certificate x509Certificate = IdPMetadataService.getInstance().getIdPMetadata().getValidX509Certificate(UsageType.SIGNING);
        BasicX509Credential credential = new BasicX509Credential(x509Certificate);

        // Validate Signature
        try {
            SignatureValidator.validate(assertion.getSignature(), credential);
        } catch (SignatureException e) {
            throw new AssertionValidationException("Could not validate assertion signature", e);
        }
    }

    private void validateAudienceRestriction(Assertion assertion) throws AssertionValidationException {
        // The assertion MUST contain an AudienceRestriction including the ServiceProvider's unique identifier as an Audience
        Conditions conditions = assertion.getConditions();
        if (conditions == null) {
            throw new AssertionValidationException("The assertion MUST contain an AudienceRestriction including the ServiceProvider's unique identifier as an Audience, no conditions present");
        }

        Configuration config = OIOSAML3Service.getConfig();
        List<AudienceRestriction> audienceRestrictions = conditions.getAudienceRestrictions();
        boolean found = false;
        for (AudienceRestriction audienceRestriction : audienceRestrictions) {
            List<Audience> audiences = audienceRestriction.getAudiences();
            for (Audience audience : audiences) {
                if (audience.getAudienceURI().equals(config.getSpEntityID())) {
                    found = true;
                }
            }
        }

        if (!found) {
            throw new AssertionValidationException("The assertion MUST contain an AudienceRestriction including the ServiceProvider's unique identifier as an Audience");
        }
    }

    private void validateSubject(Assertion assertion, AuthnRequestWrapper authnRequest) throws AssertionValidationException {
        // Assertions MUST contain one Subject
        // With a NameID element with format set to
        // urn:oasis:names:tc:SAML:2.0:nameid-format:transient or urn:oasis:names:tc:SAML:2.0:nameid-format:persistent
        Subject subject = assertion.getSubject();
        if (subject == null || subject.getNameID() == null) {
            throw new AssertionValidationException("Assertions MUST contain one Subject");
        }

        NameID nameID = subject.getNameID();
        if (nameID == null) {
            throw new AssertionValidationException("Assertions MUST contain one Subject With a NameID element ");
        }

        if (!NameID.TRANSIENT.equals(nameID.getFormat()) && !NameID.PERSISTENT.equals(nameID.getFormat())) {
            throw new AssertionValidationException("Subject NameID should have format set to urn:oasis:names:tc:SAML:2.0:nameid-format:transient or urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
        }

        // The NameID element (whether persistent or transient) SHOULD contain an SP-specific identifier based on a UUID
        String nameIDValue = nameID.getValue();
        if (nameIDValue == null || !nameIDValue.startsWith("https://data.gov.dk/model/core/eid/")) {
            throw new AssertionValidationException("Subject NameID error");
        }

        try {
            String[] split = nameIDValue.split("/uuid/");
            
            // force exception being cast if not valid UUID
            UUID.fromString(split[split.length - 1]);
        } catch (IllegalArgumentException e) {
            throw new AssertionValidationException("Subject NameID should be based on a UUID");
        }

        // Verify that the IdP returned the correct type person or professional if a specific type was requested in the AuthnRequest
        String shouldStartWith = null;
        for (String authnContextClassRef : authnRequest.getAuthnContextClassRefValues()) {
            if (Constants.ATTRIBUTE_PROFILE_PERSON.equals(authnContextClassRef)) {
                shouldStartWith = "https://data.gov.dk/model/core/eid/person";
                break;
            }

            if (Constants.ATTRIBUTE_PROFILE_PERSON.equals(authnContextClassRef)) {
                shouldStartWith = "https://data.gov.dk/model/core/eid/professional";
                break;
            }
        }

        if (shouldStartWith != null) {
            if (!nameIDValue.startsWith(shouldStartWith)) {
                throw new AssertionValidationException("Subject NameID was: " + nameIDValue + " but the AuthnRequest requested it should be of type: " + shouldStartWith);
            }
        }

        // The Subject element MUST contain at least one SubjectConfirmation
        // With conformation method of urn:oasis:names:tc:SAML:2.0:cm:bearer.
        SubjectConfirmation subjectConfirmation = null;
        for (SubjectConfirmation sc : subject.getSubjectConfirmations()) {
            if (SubjectConfirmation.METHOD_BEARER.equals(sc.getMethod())) {
                subjectConfirmation = sc;
                break;
            }
        }

        if (subjectConfirmation == null) {
            throw new AssertionValidationException("The Subject element MUST contain at least one SubjectConfirmation with conformation method of urn:oasis:names:tc:SAML:2.0:cm:bearer.");
        }

        // The SubjectConfirmation element described above MUST contain a SubjectConfirmationData with a recipient attribute containing the SP's assertion consumer service URL
        // And NotOnOrAfter attribute
        // MAY contain a NotBefore attribute
        SubjectConfirmationData subjectConfirmationData = subjectConfirmation.getSubjectConfirmationData();
        if (subjectConfirmationData == null) {
            throw new AssertionValidationException("The SubjectConfirmation element described above MUST contain a SubjectConfirmationData");
        }

        Configuration config = OIOSAML3Service.getConfig();
        if (!(config.getServletAssertionConsumerURL()).equals(subjectConfirmationData.getRecipient())) {
            throw new AssertionValidationException("The SubjectConfirmationData element MUST contain a recipient attribute containing the SP's assertion consumer service URL");
        }

        DateTime notOnOrAfter = subjectConfirmationData.getNotOnOrAfter();
        if (notOnOrAfter == null) {
            throw new AssertionValidationException("The SubjectConfirmationData element MUST a NotOnOrAfter attribute");
        }

        if (!DateTime.now().isBefore(notOnOrAfter.plusMinutes(config.getClockSkew()))) {
            throw new AssertionValidationException("This instant was validated after SubjectConfirmationData 'NotOnOrAfter' attribute plus clockskew");
        }
    }

    private void validateIssuer(Assertion assertion) throws AssertionValidationException, InternalException, ExternalException {
        // Assertions MUST contain an Issuer
        Issuer issuer = assertion.getIssuer();
        if (issuer == null) {
            throw new AssertionValidationException("Assertions MUST contain an Issuer");
        }

        // The Format attribute MUST be omitted or have a value of urn:oasis:names:tc:SAML:2.0:nameid-format:entity
        String format = issuer.getFormat();
        if (format != null && !Issuer.ENTITY.equals(format)) {
            throw new AssertionValidationException("Issuer format attribute MUST be omitted or have a value of urn:oasis:names:tc:SAML:2.0:nameid-format:entity");
        }

        // Validate that we know the issuer
        String value = issuer.getValue();
        IdPMetadataService idPMetadataService = IdPMetadataService.getInstance();
        String idpEntityID = idPMetadataService.getIdPMetadata().getEntityDescriptor().getEntityID();

        if (value == null || "".equals(value) || !Objects.equals(value, idpEntityID)) {
            throw new AssertionValidationException("Issuer does not match IdP EntityID from metadata");
        }
    }
}
