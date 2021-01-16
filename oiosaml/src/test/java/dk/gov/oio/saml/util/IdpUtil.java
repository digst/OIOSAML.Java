package dk.gov.oio.saml.util;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.namespace.QName;

import org.apache.xml.security.utils.EncryptionConstants;
import org.joda.time.DateTime;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.core.xml.schema.impl.XSAnyBuilder;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.binding.SAMLBindingSupport;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AttributeValue;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
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
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.impl.KeyStoreCredentialResolver;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.algorithm.descriptors.SignatureRSASHA256;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.Signer;

import dk.gov.oio.saml.service.OIOSAML3Service;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.security.RandomIdentifierGenerationStrategy;

public class IdpUtil {

    public static MessageContext<SAMLObject> createMessageWithAssertion(
            boolean encrypted,
            boolean validCert,
            boolean validSignature,
            String subjectNameID,
            String recipientEntityId,
            String assertionConsumerUrl,
            String inResponseToId) throws Exception {
        // Create proxy Response
        Response response = createResponse(encrypted, validCert, validSignature, subjectNameID, recipientEntityId, assertionConsumerUrl, inResponseToId);

        // Build Proxy MessageContext and add response
        MessageContext<SAMLObject> messageContext = new MessageContext<>();
        messageContext.setMessage(response);

        // Set RelayState
        SAMLBindingSupport.setRelayState(messageContext, null);

        // Set destination
        SAMLPeerEntityContext peerEntityContext = messageContext.getSubcontext(SAMLPeerEntityContext.class, true);
        SAMLEndpointContext endpointContext = peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);

        SingleSignOnService endpoint = SamlHelper.build(SingleSignOnService.class);
        endpoint.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        endpoint.setLocation(assertionConsumerUrl);

        endpointContext.setEndpoint(endpoint);

        return messageContext;
    }

    public static Response createResponse(
    		boolean encrypted,
    		boolean validCert,
    		boolean validSignature,
    		String subjectNameID,
    		String recipientEntityId,
    		String assertionConsumerUrl,
    		String inResponseToId) throws Exception {

    	DateTime issueInstant = new DateTime();

        Response response = buildSAMLObject(Response.class);
        response.setDestination(assertionConsumerUrl);
        response.setInResponseTo(inResponseToId);
        response.setIssueInstant(issueInstant);

        RandomIdentifierGenerationStrategy secureRandomIdGenerator = new RandomIdentifierGenerationStrategy();
        response.setID(secureRandomIdGenerator.generateIdentifier());

        Issuer issuer = buildSAMLObject(Issuer.class);
        issuer.setValue(TestConstants.IDP_ENTITY_ID);
        response.setIssuer(issuer);

        Status status = buildSAMLObject(Status.class);
        StatusCode statusCode = buildSAMLObject(StatusCode.class);
        statusCode.setValue(StatusCode.SUCCESS);
        status.setStatusCode(statusCode);
        response.setStatus(status);

        Assertion assertion = createAssertion(issueInstant, subjectNameID, recipientEntityId, assertionConsumerUrl);
        SignAssertion(assertion, validSignature);
        if (encrypted) {
        	EncryptedAssertion encryptedAssertion = encryptAssertion(assertion, validCert);
            response.getEncryptedAssertions().add(encryptedAssertion);
        }
        else {
        	response.getAssertions().add(assertion);
        }

        return response;
    }

    public static MessageContext<SAMLObject> createMessageWithLogoutResponse(LogoutRequest logoutRequest, String destination, String statusCode) throws Exception {
        // Create message context
        MessageContext<SAMLObject> messageContext = new MessageContext<>();

        // Create AuthnRequest
        LogoutResponse logoutResponse = createLogoutResponse(destination, logoutRequest, statusCode);
        messageContext.setMessage(logoutResponse);

        // Destination
        SAMLPeerEntityContext peerEntityContext = messageContext.getSubcontext(SAMLPeerEntityContext.class, true);
        SAMLEndpointContext endpointContext = peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);

        SingleSignOnService endpoint = SamlHelper.build(SingleSignOnService.class);
        endpoint.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
        endpoint.setLocation(destination);

        endpointContext.setEndpoint(endpoint);

        // Signing info
        SignatureSigningParameters signatureSigningParameters = new SignatureSigningParameters();
        signatureSigningParameters.setSigningCredential(getX509Credential(true));
        signatureSigningParameters.setSignatureAlgorithm(OIOSAML3Service.getConfig().getSignatureAlgorithm());
        messageContext.getSubcontext(SecurityParametersContext.class, true).setSignatureSigningParameters(signatureSigningParameters);

        return messageContext;
    }

    private static LogoutResponse createLogoutResponse(String destination, LogoutRequest logoutRequest, String statusCodeValue) throws InitializationException {
        LogoutResponse logoutResponse = SamlHelper.build(LogoutResponse.class);

        RandomIdentifierGenerationStrategy randomIdentifierGenerator = new RandomIdentifierGenerationStrategy();
        String id = randomIdentifierGenerator.generateIdentifier();

        logoutResponse.setID(id);
        logoutResponse.setDestination(destination);
        logoutResponse.setIssueInstant(new DateTime());
        logoutResponse.setInResponseTo(logoutRequest.getID());

        // Create Issuer
        Issuer issuer = SamlHelper.build(Issuer.class);
        logoutResponse.setIssuer(issuer);
        issuer.setValue(OIOSAML3Service.getConfig().getSpEntityID());

        Status status = SamlHelper.build(Status.class);
        logoutResponse.setStatus(status);

        StatusCode statusCode = SamlHelper.build(StatusCode.class);
        status.setStatusCode(statusCode);
        statusCode.setValue(statusCodeValue);

        return logoutResponse;
    }

    public static MessageContext<SAMLObject> createMessageWithLogoutRequest(String nameID, String nameIDFormat, String destination) throws Exception {
        // Create message context
        MessageContext<SAMLObject> messageContext = new MessageContext<>();

        // Create AuthnRequest
        LogoutRequest outgoingLogoutRequest = createLogoutRequest(nameID, nameIDFormat, destination);
        messageContext.setMessage(outgoingLogoutRequest);

        // Destination
        SAMLPeerEntityContext peerEntityContext = messageContext.getSubcontext(SAMLPeerEntityContext.class, true);
        SAMLEndpointContext endpointContext = peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);

        SingleSignOnService endpoint = SamlHelper.build(SingleSignOnService.class);
        endpointContext.setEndpoint(endpoint);

        endpoint.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
        endpoint.setLocation(destination);

        // Signing info
        SignatureSigningParameters signatureSigningParameters = new SignatureSigningParameters();
        signatureSigningParameters.setSigningCredential(getX509Credential(true));
        signatureSigningParameters.setSignatureAlgorithm(OIOSAML3Service.getConfig().getSignatureAlgorithm());
        messageContext.getSubcontext(SecurityParametersContext.class, true).setSignatureSigningParameters(signatureSigningParameters);

        return messageContext;
    }

    public static LogoutRequest createLogoutRequest(String nameID, String nameIDFormat, String destination) throws InitializationException {
        LogoutRequest outgoingLR = SamlHelper.build(LogoutRequest.class);

        // Set ID
        RandomIdentifierGenerationStrategy secureRandomIdGenerator = new RandomIdentifierGenerationStrategy();
        String id = secureRandomIdGenerator.generateIdentifier();
        outgoingLR.setID(id);

        outgoingLR.setDestination(destination);
        outgoingLR.setIssueInstant(new DateTime());

        // Create Issuer
        Issuer issuer = SamlHelper.build(Issuer.class);
        outgoingLR.setIssuer(issuer);

        issuer.setValue(OIOSAML3Service.getConfig().getSpEntityID());

        // NameID
        NameID nameIDObj = SamlHelper.build(NameID.class);
        outgoingLR.setNameID(nameIDObj);

        nameIDObj.setFormat(nameIDFormat);
        nameIDObj.setValue(nameID);

        return outgoingLR;
    }

    private static EncryptedAssertion encryptAssertion(Assertion assertion, boolean validCert) throws Exception {
    	X509Certificate certificate = getSPCertificate(validCert);

        Credential keyEncryptionCredential = new BasicX509Credential(certificate);
        DataEncryptionParameters encParams = new DataEncryptionParameters();

        encParams.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256);

        KeyEncryptionParameters kekParams = new KeyEncryptionParameters();
        kekParams.setEncryptionCredential(keyEncryptionCredential);
        kekParams.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);

        Encrypter samlEncrypter = new Encrypter(encParams, kekParams);
        samlEncrypter.setKeyPlacement(Encrypter.KeyPlacement.PEER);

        return samlEncrypter.encrypt(assertion);
    }

    private static X509Certificate getSPCertificate(boolean validCert) throws Exception {        
        String resourceName = (validCert) ? "sp.pem" : "invalid.pem";

        ClassLoader classLoader = IdpUtil.class.getClassLoader();
        FileInputStream fis = new FileInputStream(classLoader.getResource(resourceName).getFile());

        CertificateFactory instance = CertificateFactory.getInstance("X.509");
        return (X509Certificate) instance.generateCertificate(fis);
	}

	private static void SignAssertion(Assertion assertion, boolean validSignature) throws Exception {
        Signature signature = buildSAMLObject(Signature.class);

        BasicX509Credential x509Credential = getX509Credential(validSignature);
        SignatureRSASHA256 signatureRSASHA256 = new SignatureRSASHA256();

        signature.setSigningCredential(x509Credential);
        signature.setCanonicalizationAlgorithm(CanonicalizationMethod.EXCLUSIVE);
        signature.setSignatureAlgorithm(signatureRSASHA256.getURI());
        signature.setKeyInfo(getPublicKeyInfo(x509Credential));

        assertion.setSignature(signature);

        AssertionMarshaller marshaller = new AssertionMarshaller();
        marshaller.marshall(assertion);

        Signer.signObject(signature);
    }

    private static Assertion createAssertion(DateTime issueInstant, String subjectNameID, String recipientEntityId, String assertionConsumerUrl) {
        RandomIdentifierGenerationStrategy secureRandomIdGenerator = new RandomIdentifierGenerationStrategy();
        String id = secureRandomIdGenerator.generateIdentifier();

        // Create assertion
        Assertion assertion = buildSAMLObject(Assertion.class);
        assertion.setIssueInstant(issueInstant);

        //AuthnStatement
        AuthnContextClassRef authnContextClassRef = buildSAMLObject(AuthnContextClassRef.class);
        authnContextClassRef.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");

        AuthnContext authnContext = buildSAMLObject(AuthnContext.class);
        authnContext.setAuthnContextClassRef(authnContextClassRef);

        AuthnStatement authnStatement = buildSAMLObject(AuthnStatement.class);
        authnStatement.setAuthnInstant(new DateTime());
        authnStatement.setSessionIndex(id);
        assertion.setID(id);

        authnStatement.setAuthnContext(authnContext);

        assertion.getAuthnStatements().add(authnStatement);

        //AttributeStatement
        AttributeStatement attributeStatement = buildSAMLObject(AttributeStatement.class);
        List<Attribute> attributes = attributeStatement.getAttributes();

        attributes.add(createSimpleAttribute("https://data.gov.dk/model/core/specVersion", "OIO-SAML-3.0"));
        attributes.add(createSimpleAttribute("https://data.gov.dk/concept/core/nsis/loa", Constants.LOA_SUBSTANTIAL));
        assertion.getAttributeStatements().add(attributeStatement);

        Issuer issuer = buildSAMLObject(Issuer.class);
        issuer.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:entity");
        issuer.setValue(TestConstants.IDP_ENTITY_ID);
        assertion.setIssuer(issuer);

        Subject subject = buildSAMLObject(Subject.class);
        NameID nameID = buildSAMLObject(NameID.class);
        nameID.setFormat(NameIDType.PERSISTENT);
        nameID.setValue(subjectNameID);
        subject.setNameID(nameID);

        SubjectConfirmation subjectConfirmation = buildSAMLObject(SubjectConfirmation.class);
        subjectConfirmation.setMethod("urn:oasis:names:tc:SAML:2.0:cm:bearer");

        SubjectConfirmationData subjectConfirmationData = buildSAMLObject(SubjectConfirmationData.class);
        subjectConfirmationData.setRecipient(assertionConsumerUrl);
        subjectConfirmationData.setNotOnOrAfter(new DateTime(issueInstant).plusMinutes(5));

        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);

        subject.getSubjectConfirmations().add(subjectConfirmation);

        assertion.setSubject(subject);

        AudienceRestriction audienceRestriction = buildSAMLObject(AudienceRestriction.class);
        Audience audience = buildSAMLObject(Audience.class);
        audience.setAudienceURI(recipientEntityId);
        audienceRestriction.getAudiences().add(audience);

        Conditions conditions = buildSAMLObject(Conditions.class);
        conditions.setNotBefore(issueInstant);
        conditions.setNotOnOrAfter(new DateTime(issueInstant).plusHours(1));
        conditions.getAudienceRestrictions().add(audienceRestriction);
        assertion.setConditions(conditions);

        return assertion;
    }

    private static Attribute createSimpleAttribute(String attributeName, String attributeValue) {
        Attribute attribute = buildSAMLObject(Attribute.class);

        attribute.setName(attributeName);
        attribute.setNameFormat("urn:oasis:names:tc:SAML:2.0:attrname-format:basic");

        XSAnyBuilder xsAnyBuilder = new XSAnyBuilder();
        XSAny value = xsAnyBuilder.buildObject(SAMLConstants.SAML20_NS, AttributeValue.DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML20_PREFIX);

        value.setTextContent(attributeValue);
        attribute.getAttributeValues().add(value);

        return attribute;
    }
    
    @SuppressWarnings("unchecked")
	private static <T> T buildSAMLObject(final Class<T> clazz) {
        T object = null;

        try {
            XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
            QName defaultElementName = (QName) clazz.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);
            object = (T) builderFactory.getBuilder(defaultElementName).buildObject(defaultElementName);
        }
        catch (IllegalAccessException | NoSuchFieldException e) {
            throw new IllegalArgumentException("Could not create SAML object");
        }

        return object;
    }
    
    private static BasicX509Credential getX509Credential(boolean validSignature) throws Exception {
        String resourceName = (validSignature) ? "idp.pfx" : "idp-invalid.pfx";

        ClassLoader classLoader = IdpUtil.class.getClassLoader();
        FileInputStream fis = new FileInputStream(classLoader.getResource(resourceName).getFile());

    	KeyStore ks = KeyStore.getInstance("PKCS12");
    	ks.load(fis, "Test1234".toCharArray());

        Map<String, String> passwords = new HashMap<>();
        passwords.put(ks.aliases().nextElement(), "Test1234");
        KeyStoreCredentialResolver resolver = new KeyStoreCredentialResolver(ks, passwords);

        CriteriaSet criteria = new CriteriaSet();
        EntityIdCriterion entityIdCriterion = new EntityIdCriterion("1");
        criteria.add(entityIdCriterion);

        return (BasicX509Credential) resolver.resolveSingle(criteria);
    }
    
    private static KeyInfo getPublicKeyInfo(BasicX509Credential cred) throws Exception {
        X509KeyInfoGeneratorFactory x509KeyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
        x509KeyInfoGeneratorFactory.setEmitEntityCertificate(true);
        KeyInfoGenerator keyInfoGenerator = x509KeyInfoGeneratorFactory.newInstance();

        return keyInfoGenerator.generate(cred);
    }
}
