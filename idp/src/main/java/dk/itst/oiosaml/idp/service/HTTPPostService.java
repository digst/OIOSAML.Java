package dk.itst.oiosaml.idp.service;

import dk.itst.oiosaml.idp.config.Session;
import dk.itst.oiosaml.idp.dao.model.enums.AttributeProfile;
import dk.itst.oiosaml.idp.util.Constants;
import lombok.extern.log4j.Log4j2;
import net.shibboleth.utilities.java.support.security.RandomIdentifierGenerationStrategy;
import org.apache.xml.security.utils.EncryptionConstants;
import org.bouncycastle.util.encoders.Base64;
import org.joda.time.DateTime;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.core.xml.schema.impl.XSAnyBuilder;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AttributeValue;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.saml2.core.impl.AssertionMarshaller;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.algorithm.descriptors.SignatureRSASHA256;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.X509Certificate;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.Signer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.util.List;
import java.util.Optional;

@Service
@Log4j2
public class HTTPPostService {

    @Autowired
    private ValidationService validationService;

    @Autowired
    private HTTPRedirectService httpRedirectService;

    @Autowired
    private CredentialService credentialService;

    @Autowired
    private OpenSAMLHelperService samlBuilder;

    @Autowired
    private MetadataService metadataService;

    public Response createResponse(Session session, AuthnRequest authnRequest) {
        DateTime issueInstant = new DateTime();
        Assertion assertion = createAssertion(issueInstant, session, authnRequest);

        SignAssertion(assertion);
        EncryptedAssertion encryptedAssertion = null;
        try {
            encryptedAssertion = encryptAssertion(assertion);
        } catch (Exception e) {
            e.printStackTrace();
        }


        Response response = samlBuilder.buildSAMLObject(Response.class);
        response.setDestination(authnRequest.getAssertionConsumerServiceURL());
        response.setInResponseTo(authnRequest.getID());
        response.setIssueInstant(issueInstant);

        RandomIdentifierGenerationStrategy secureRandomIdGenerator = new RandomIdentifierGenerationStrategy();
        String id = secureRandomIdGenerator.generateIdentifier();
        response.setID(id);

        Issuer issuer = samlBuilder.buildSAMLObject(Issuer.class);
        issuer.setValue("https://localhost:7080");
        response.setIssuer(issuer);

        Status status = samlBuilder.buildSAMLObject(Status.class);
        StatusCode statusCode = samlBuilder.buildSAMLObject(StatusCode.class);
        statusCode.setValue(StatusCode.SUCCESS);
        status.setStatusCode(statusCode);
        response.setStatus(status);

//        response.getAssertions().add(assertion);
        response.getEncryptedAssertions().add(encryptedAssertion);

        return response;
    }

    private EncryptedAssertion encryptAssertion(Assertion assertion) throws Exception {
        // Assume this contains a recipient's RSA public key
        Credential keyEncryptionCredential;
        SPSSODescriptor spssod = metadataService.getSPMetadata().getSPSSODescriptor("urn:oasis:names:tc:SAML:2.0:protocol");
        Optional<KeyDescriptor> first = spssod.getKeyDescriptors().stream()
                .filter(keyDescriptor -> keyDescriptor.getUse().equals(UsageType.ENCRYPTION)).findFirst();

        if (!first.isPresent()) {
            throw new Exception();
        }

        X509Certificate x509Certificate = first.get().getKeyInfo().getX509Datas().get(0).getX509Certificates().get(0);


        x509Certificate.getValue();


        CertificateFactory instance = CertificateFactory.getInstance("X.509");
        java.security.cert.X509Certificate certificate = (java.security.cert.X509Certificate) instance.generateCertificate(new ByteArrayInputStream(Base64.decode(x509Certificate.getValue())));
        keyEncryptionCredential = new BasicX509Credential(certificate);

        DataEncryptionParameters encParams = new DataEncryptionParameters();

        encParams.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256);

        KeyEncryptionParameters kekParams = new KeyEncryptionParameters();
        kekParams.setEncryptionCredential(keyEncryptionCredential);
        kekParams.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);

        Encrypter samlEncrypter = new Encrypter(encParams, kekParams);
        samlEncrypter.setKeyPlacement(Encrypter.KeyPlacement.PEER);

        return samlEncrypter.encrypt(assertion);
    }

    private void SignAssertion(Assertion assertion) {
        // Prepare Assertion for Signing
        Signature signature = samlBuilder.buildSAMLObject(Signature.class);

        BasicX509Credential x509Credential = credentialService.getX509Credential();
        SignatureRSASHA256 signatureRSASHA256 = new SignatureRSASHA256();

        signature.setSigningCredential(x509Credential);
        signature.setCanonicalizationAlgorithm(CanonicalizationMethod.EXCLUSIVE);
        signature.setSignatureAlgorithm(signatureRSASHA256.getURI());
        signature.setKeyInfo(credentialService.getPublicKeyInfo());

        assertion.setSignature(signature);


        // Sign Assertion
        try {
            AssertionMarshaller marshaller = new AssertionMarshaller();
            marshaller.marshall(assertion);

            Signer.signObject(signature);

        } catch (MarshallingException | SignatureException e) {
            log.error("Signing failed", e);
        }
    }


    private Assertion createAssertion(DateTime issueInstant, Session session, AuthnRequest authnRequest) {
        RandomIdentifierGenerationStrategy secureRandomIdGenerator = new RandomIdentifierGenerationStrategy();
        String id = secureRandomIdGenerator.generateIdentifier();

        // Create assertion
        Assertion assertion = samlBuilder.buildSAMLObject(Assertion.class);
        assertion.setIssueInstant(issueInstant);

        //AuthnStatement
        AuthnStatement authnStatement = samlBuilder.buildSAMLObject(AuthnStatement.class);
        authnStatement.setAuthnInstant(new DateTime());
        authnStatement.setSessionIndex(id);

        assertion.setID(id);

        AuthnContext authnContext = samlBuilder.buildSAMLObject(AuthnContext.class);

        AuthnContextClassRef authnContextClassRef = samlBuilder.buildSAMLObject(AuthnContextClassRef.class);
        authnContextClassRef.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");

        authnContext.setAuthnContextClassRef(authnContextClassRef);

        authnStatement.setAuthnContext(authnContext);

        assertion.getAuthnStatements().add(authnStatement);


        //AttributeStatement
        AttributeStatement attributeStatement = samlBuilder.buildSAMLObject(AttributeStatement.class);
        List<Attribute> attributes = attributeStatement.getAttributes();

        if (session.isAddRequiredAttributes()) {
            attributes.add(createSimpleAttribute(Constants.SPEC_VERSION, Constants.SPEC_VERSION_OIOSAML30));
        }

        if (session.getLevelOfAssurance() != null) {
            attributes.add(createSimpleAttribute(Constants.LEVEL_OF_ASSURANCE, session.getLevelOfAssurance().getText()));
        }

        if (session.getAttributeProfile() != null) {
            if (session.getAttributeProfile().equals(AttributeProfile.PROFESSIONAL)) {
                attributes.add(createSimpleAttribute(Constants.CVR, Constants.CVR_VALUE));
                attributes.add(createSimpleAttribute(Constants.ORGANISATION_NAME, Constants.ORGANISATION_NAME_VALUE));
            }
        }

        assertion.getAttributeStatements().add(attributeStatement);


        //Issuer
        Issuer issuer = samlBuilder.buildSAMLObject(Issuer.class);
        issuer.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:entity");
        issuer.setValue("https://localhost:7080");
        assertion.setIssuer(issuer);


        //Subject
        Subject subject = samlBuilder.buildSAMLObject(Subject.class);
        if (session.isCorrectNameID()) {
            NameID nameID = samlBuilder.buildSAMLObject(NameID.class);
            nameID.setFormat(NameIDType.PERSISTENT);
            nameID.setValue(session.getUsername());
            subject.setNameID(nameID);
        }

        SubjectConfirmation subjectConfirmation = samlBuilder.buildSAMLObject(SubjectConfirmation.class);
        subjectConfirmation.setMethod("urn:oasis:names:tc:SAML:2.0:cm:bearer");

        SubjectConfirmationData subjectConfirmationData = samlBuilder.buildSAMLObject(SubjectConfirmationData.class);
        subjectConfirmationData.setRecipient(authnRequest.getAssertionConsumerServiceURL()); //i think this should be verified against metadata
        subjectConfirmationData.setNotOnOrAfter(new DateTime(issueInstant).plusMinutes(5));

        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);

        subject.getSubjectConfirmations().add(subjectConfirmation);

        assertion.setSubject(subject);


        // Audience restriction
        AudienceRestriction audienceRestriction = samlBuilder.buildSAMLObject(AudienceRestriction.class);

        Audience audience = samlBuilder.buildSAMLObject(Audience.class);
        audience.setAudienceURI(authnRequest.getIssuer().getValue()); //This should be the SP's unique id

        audienceRestriction.getAudiences().add(audience);

        Conditions conditions = samlBuilder.buildSAMLObject(Conditions.class);
        conditions.setNotBefore(issueInstant);
        conditions.setNotOnOrAfter(new DateTime(issueInstant).plusHours(1));

        conditions.getAudienceRestrictions().add(audienceRestriction);

        assertion.setConditions(conditions);


        return assertion;
    }

    private Attribute createSimpleAttribute(String attributeName, String attributeValue) {
        Attribute attribute = samlBuilder.buildSAMLObject(Attribute.class);

        attribute.setName(attributeName);
        attribute.setNameFormat(Constants.ATTRIBUTE_VALUE_FORMAT);

        XSAnyBuilder xsAnyBuilder = new XSAnyBuilder();
        XSAny value = xsAnyBuilder.buildObject(SAMLConstants.SAML20_NS, AttributeValue.DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML20_PREFIX);

        value.setTextContent(attributeValue);
        attribute.getAttributeValues().add(value);

        return attribute;
    }
}
