package dk.gov.oio.saml.service;

import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.AttributeConsumingService;
import org.opensaml.saml.saml2.metadata.ContactPerson;
import org.opensaml.saml.saml2.metadata.ContactPersonTypeEnumeration;
import org.opensaml.saml.saml2.metadata.EmailAddress;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import org.opensaml.saml.saml2.metadata.RequestedAttribute;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.ServiceName;
import org.opensaml.saml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml.saml2.metadata.impl.EntityDescriptorMarshaller;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.w3c.dom.Element;

import dk.gov.oio.saml.config.Configuration;
import dk.gov.oio.saml.util.InternalException;
import dk.gov.oio.saml.util.SamlHelper;

public class SPMetadataService {
    // Single instance
    private static SPMetadataService singleInstance = new SPMetadataService();

    public static SPMetadataService getInstance() {
        return singleInstance;
    }

    // SPMetadata service
    private String marshalledMetadata;

    public String getMarshalledMetadata() throws InternalException, InitializationException {
        if (marshalledMetadata == null) {
            createMetadata();
        }
        return marshalledMetadata;
    }

    public void createMetadata() throws InternalException, InitializationException {
        Configuration config = OIOSAML3Service.getConfig();

        EntityDescriptor entityDescriptor = createEntityDescriptor(config.getSpEntityID());

        // Create SPSSODescriptor
        SPSSODescriptor spssoDescriptor = SamlHelper.build(SPSSODescriptor.class);
        entityDescriptor.getRoleDescriptors().add(spssoDescriptor);

        spssoDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);
        spssoDescriptor.setAuthnRequestsSigned(true);
        spssoDescriptor.setWantAssertionsSigned(true);

        // NameID Format
        NameIDFormat nameIDFormat = SamlHelper.build(NameIDFormat.class);
        nameIDFormat.setFormat(config.getNameIDFormat());
		spssoDescriptor.getNameIDFormats().add(nameIDFormat);

		// set requested attributes
		ServiceName serviceName = SamlHelper.build(ServiceName.class);
		serviceName.setXMLLang("da");
		serviceName.setValue(config.getSpEntityID());

		// These are needed for NemLogin-2, might not be needed in the future
		AttributeConsumingService attributeConsumingService = SamlHelper.build(AttributeConsumingService.class);
		attributeConsumingService.setIsDefault(true);
		attributeConsumingService.getNames().add(serviceName);
		attributeConsumingService.getRequestAttributes().add(buildRequiredAttribute("https://data.gov.dk/model/core/specVersion", true));
		attributeConsumingService.getRequestAttributes().add(buildRequiredAttribute("https://data.gov.dk/model/core/eid/bootstrapToken", false));
		attributeConsumingService.getRequestAttributes().add(buildRequiredAttribute("https://data.gov.dk/model/core/eid/privilegesIntermediate", false));
		attributeConsumingService.getRequestAttributes().add(buildRequiredAttribute("https://data.gov.dk/concept/core/nsis/loa", true));
		attributeConsumingService.getRequestAttributes().add(buildRequiredAttribute("https://data.gov.dk/concept/core/nsis/ial", false));
		attributeConsumingService.getRequestAttributes().add(buildRequiredAttribute("https://data.gov.dk/concept/core/nsis/aal", false));
		attributeConsumingService.getRequestAttributes().add(buildRequiredAttribute("https://data.gov.dk/model/core/eid/fullName", false));
		attributeConsumingService.getRequestAttributes().add(buildRequiredAttribute("https://data.gov.dk/model/core/eid/firstName", false));
		attributeConsumingService.getRequestAttributes().add(buildRequiredAttribute("https://data.gov.dk/model/core/eid/lastName", false));
		attributeConsumingService.getRequestAttributes().add(buildRequiredAttribute("https://data.gov.dk/model/core/eid/email", false));
		attributeConsumingService.getRequestAttributes().add(buildRequiredAttribute("https://data.gov.dk/model/core/eid/cprNumber", false));
		attributeConsumingService.getRequestAttributes().add(buildRequiredAttribute("https://data.gov.dk/model/core/eid/age", false));
		attributeConsumingService.getRequestAttributes().add(buildRequiredAttribute("https://data.gov.dk/model/core/eid/cprUuid", false));
		attributeConsumingService.getRequestAttributes().add(buildRequiredAttribute("https://data.gov.dk/model/core/eid/dateOfBirth", false));
		attributeConsumingService.getRequestAttributes().add(buildRequiredAttribute("https://data.gov.dk/model/core/eid/person/pid", false));
		attributeConsumingService.getRequestAttributes().add(buildRequiredAttribute("https://data.gov.dk/model/core/eid/professional/uuid/persistent", false));
		attributeConsumingService.getRequestAttributes().add(buildRequiredAttribute("https://data.gov.dk/model/core/eid/professional/rid", false));
		attributeConsumingService.getRequestAttributes().add(buildRequiredAttribute("https://data.gov.dk/model/core/eid/professional/cvr", true));
		attributeConsumingService.getRequestAttributes().add(buildRequiredAttribute("https://data.gov.dk/model/core/eid/professional/orgName", true));
		attributeConsumingService.getRequestAttributes().add(buildRequiredAttribute("https://data.gov.dk/model/core/eid/professional/productionUnit", false));
		attributeConsumingService.getRequestAttributes().add(buildRequiredAttribute("https://data.gov.dk/model/core/eid/professional/seNumber", false));
	      
		spssoDescriptor.getAttributeConsumingServices().add(attributeConsumingService);
		
        // Encryption and Signing descriptors
        List<KeyDescriptor> keyDescriptors = spssoDescriptor.getKeyDescriptors();
        keyDescriptors.addAll(getKeyDescriptors());

        // Create AssertionConsumerService endpoint
        AssertionConsumerService assertionConsumerService = SamlHelper.build(AssertionConsumerService.class);
        spssoDescriptor.getAssertionConsumerServices().add(assertionConsumerService);
        assertionConsumerService.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        assertionConsumerService.setLocation(config.getServletAssertionConsumerURL());
        assertionConsumerService.setIsDefault(true);
        assertionConsumerService.setIndex(0);

        // Create SLO endpoint for HTTP-Redirect
        SingleLogoutService singleLogoutService = SamlHelper.build(SingleLogoutService.class);
        spssoDescriptor.getSingleLogoutServices().add(singleLogoutService);

        singleLogoutService.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
        singleLogoutService.setLocation(config.getServletLogoutURL());
        singleLogoutService.setResponseLocation(config.getServletLogoutResponseURL());
        
        // Create SLO endpoint for POST
        singleLogoutService = SamlHelper.build(SingleLogoutService.class);
        spssoDescriptor.getSingleLogoutServices().add(singleLogoutService);

        singleLogoutService.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        singleLogoutService.setLocation(config.getServletLogoutURL());
        singleLogoutService.setResponseLocation(config.getServletLogoutResponseURL());

        // Create SLO endpoint for SOAP
        singleLogoutService = SamlHelper.build(SingleLogoutService.class);
        spssoDescriptor.getSingleLogoutServices().add(singleLogoutService);

        singleLogoutService.setBinding(SAMLConstants.SAML2_SOAP11_BINDING_URI);
        singleLogoutService.setLocation(config.getServletLogoutURL());
        singleLogoutService.setResponseLocation(config.getServletLogoutResponseURL());

        String contactEmail = config.getContactEmail();
        if (contactEmail != null && !"".equals(contactEmail)) {
            EmailAddress emailAddress = SamlHelper.build(EmailAddress.class);
            emailAddress.setAddress(contactEmail);

            ContactPerson contactPerson = SamlHelper.build(ContactPerson.class);
            contactPerson.setType(ContactPersonTypeEnumeration.TECHNICAL);
            contactPerson.getEmailAddresses().add(emailAddress);
            spssoDescriptor.getContactPersons().add(contactPerson);
        }


        // Marshall and send EntityDescriptor
        marshalledMetadata = marshallMetadata(entityDescriptor);
    }

    private RequestedAttribute buildRequiredAttribute(String attribute, boolean required) {
		RequestedAttribute requestedAttribute = SamlHelper.build(RequestedAttribute.class);
		requestedAttribute.setName(attribute);
		requestedAttribute.setFriendlyName("");
		requestedAttribute.setNameFormat("urn:oasis:names:tc:SAML:2.0:attrname-format:uri");
		requestedAttribute.setIsRequired(required);

		return requestedAttribute;
	}

	private String marshallMetadata(EntityDescriptor entityDescriptor) throws InternalException {
        try {
            EntityDescriptorMarshaller entityDescriptorMarshaller = new EntityDescriptorMarshaller();
            Element element = entityDescriptorMarshaller.marshall(entityDescriptor);
            Source source = new DOMSource(element);

            TransformerFactory transFactory = TransformerFactory.newInstance();
            Transformer transformer = transFactory.newTransformer();

            transformer.setOutputProperty(OutputKeys.METHOD, "xml");
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");

            StringWriter buffer = new StringWriter();
            transformer.transform(source, new StreamResult(buffer));

            return buffer.toString();
        }
        catch (TransformerException | MarshallingException e) {
            throw new InternalException("Could not marshall metadata", e);
        }
    }

    private EntityDescriptor createEntityDescriptor(String entityID) {
        EntityDescriptor entityDescriptor = SamlHelper.build(EntityDescriptor.class);
        entityDescriptor.setEntityID(entityID);
        entityDescriptor.setID("_" + UUID.nameUUIDFromBytes(entityID.getBytes()).toString());
        return entityDescriptor;
    }

    private List<KeyDescriptor> getKeyDescriptors() throws InternalException {
        try {
            ArrayList<KeyDescriptor> keyDescriptors = new ArrayList<>();
            CredentialService credentialService = CredentialService.getInstance();

            BasicX509Credential primaryBasicX509Credential = credentialService.getPrimaryBasicX509Credential();
            keyDescriptors.add(getKeyDescriptor(UsageType.SIGNING, credentialService.getPublicKeyInfo(primaryBasicX509Credential)));
            keyDescriptors.add(getKeyDescriptor(UsageType.ENCRYPTION, credentialService.getPublicKeyInfo(primaryBasicX509Credential)));


            BasicX509Credential secondaryBasicX509Credential = credentialService.getSecondaryBasicX509Credential();
            if (secondaryBasicX509Credential != null) {
                keyDescriptors.add(getKeyDescriptor(UsageType.SIGNING, credentialService.getPublicKeyInfo(secondaryBasicX509Credential)));
                keyDescriptors.add(getKeyDescriptor(UsageType.ENCRYPTION, credentialService.getPublicKeyInfo(secondaryBasicX509Credential)));
            }

            return keyDescriptors;
        } catch (InitializationException e) {
            throw new InternalException("CredentialService was not initialized", e);
        }
    }

    private KeyDescriptor getKeyDescriptor(UsageType usageType, KeyInfo keyInfo) {
        KeyDescriptor keyDescriptor = SamlHelper.build(KeyDescriptor.class);
        keyDescriptor.setUse(usageType);
        keyDescriptor.setKeyInfo(keyInfo);
        return  keyDescriptor;
    }
}