package dk.itst.oiosaml.idp.controller.saml;

import dk.itst.oiosaml.idp.service.CredentialService;
import dk.itst.oiosaml.idp.service.OpenSAMLHelperService;
import lombok.extern.log4j.Log4j2;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.ContactPerson;
import org.opensaml.saml.saml2.metadata.ContactPersonTypeEnumeration;
import org.opensaml.saml.saml2.metadata.EmailAddress;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml.saml2.metadata.impl.EntityDescriptorMarshaller;
import org.opensaml.security.credential.UsageType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Element;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringWriter;

@Log4j2
@RestController
public class MetadataController {

    @Autowired
    private OpenSAMLHelperService samlHelper;

    @Autowired
    private CredentialService credentialService;

    @GetMapping(value = "/saml/metadata", produces = MediaType.APPLICATION_XML_VALUE)
    @ResponseBody
    public String metadataEndpoint() {
        EntityDescriptor entityDescriptor = samlHelper.buildSAMLObject(EntityDescriptor.class);

        IDPSSODescriptor idpssoDescriptor = samlHelper.buildSAMLObject(IDPSSODescriptor.class);
        idpssoDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);
        idpssoDescriptor.setWantAuthnRequestsSigned(true);

        //Signing cert
        KeyDescriptor signingKeyDescriptor = samlHelper.buildSAMLObject(KeyDescriptor.class);
        signingKeyDescriptor.setUse(UsageType.SIGNING);
        signingKeyDescriptor.setKeyInfo(credentialService.getPublicKeyInfo());

        idpssoDescriptor.getKeyDescriptors().add(signingKeyDescriptor);

        //Signing cert
        KeyDescriptor encryptionKeyDescriptor = samlHelper.buildSAMLObject(KeyDescriptor.class);
        signingKeyDescriptor.setUse(UsageType.ENCRYPTION);
        signingKeyDescriptor.setKeyInfo(credentialService.getPublicKeyInfo());

        idpssoDescriptor.getKeyDescriptors().add(encryptionKeyDescriptor);


        //Single Sign-On endpoint
        SingleSignOnService singleSignOnMetadata = samlHelper.buildSAMLObject(SingleSignOnService.class);
        singleSignOnMetadata.setBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
        singleSignOnMetadata.setLocation("https://localhost:7080/saml/sso");
        idpssoDescriptor.getSingleSignOnServices().add(singleSignOnMetadata);


        //Single Log-out endpoint
        SingleLogoutService singleLogoutMetadata = samlHelper.buildSAMLObject(SingleLogoutService.class);
        singleLogoutMetadata.setBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
        singleLogoutMetadata.setLocation("https://localhost:7080/saml/slo");
        idpssoDescriptor.getSingleLogoutServices().add(singleLogoutMetadata);


        //Contact email for technical support
        ContactPerson contactPerson = samlHelper.buildSAMLObject(ContactPerson.class);
        contactPerson.setType(ContactPersonTypeEnumeration.TECHNICAL);
        EmailAddress email = samlHelper.buildSAMLObject(EmailAddress.class);
        email.setAddress("TEMPADDR@digital-identity.dk");
        contactPerson.getEmailAddresses().add(email);
        idpssoDescriptor.getContactPersons().add(contactPerson);


        entityDescriptor.getRoleDescriptors().add(idpssoDescriptor);

        EntityDescriptorMarshaller entityDescriptorMarshaller = new EntityDescriptorMarshaller();


        try {
            Element element = entityDescriptorMarshaller.marshall(entityDescriptor);


            Source source = new DOMSource(element);
            TransformerFactory transFactory = TransformerFactory.newInstance();
            Transformer transformer = transFactory.newTransformer();
            StringWriter buffer = new StringWriter();

            transformer.setOutputProperty(OutputKeys.METHOD, "xml");
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
            transformer.transform(source, new StreamResult(buffer));


            return buffer.toString();
        } catch (MarshallingException | TransformerException e) {
            e.printStackTrace();
        }
        return null;
    }
}
