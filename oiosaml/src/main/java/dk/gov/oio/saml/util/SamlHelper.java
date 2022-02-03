package dk.gov.oio.saml.util;

import java.util.HashMap;
import java.util.Map;
import javax.xml.namespace.QName;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.XMLRuntimeException;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AttributeValue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

public class SamlHelper {
    private static final Logger log = LoggerFactory.getLogger(SamlHelper.class);

    @SuppressWarnings("unchecked")
    public static <T> T build(final Class<T> clazz) {
        T object = null;
        try {
            XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
            QName defaultElementName = (QName) clazz.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);
            object = (T) builderFactory.getBuilder(defaultElementName).buildObject(defaultElementName);
        } catch (IllegalAccessException | NoSuchFieldException e) {
            throw new IllegalArgumentException("Could not create SAML object");
        }

        return object;
    }

    public static Map<String, String> extractAttributeValues(AttributeStatement attributeStatement) {
        Map<String, String> result = new HashMap<>();

        for (Attribute attribute : attributeStatement.getAttributes()) {
            String name = attribute.getName();
            String value = extractAttributeValueValue(attribute);

            // never extract CPR
            if ("dk:gov:saml:attribute:CprNumberIdentifier".equals(name)) {
                continue;
            }

            if (name != null && value != null && !name.isEmpty() && !value.isEmpty()) {
                result.put(name, value);
            }
        }

        return result;
    }

    public static Element marshallObject(XMLObject object) throws MarshallingException {
        if (object.getDOM() == null) {
            Marshaller m = getMarshaller(object);

            if (m == null) {
                throw new IllegalArgumentException("No unmarshaller for " + object);
            }

            return m.marshall(object);
        }

        return object.getDOM();
    }

    public static XMLObject unmarshallObject(Element marshalledObject) throws UnmarshallingException {
        Unmarshaller unmarshaller = getUnmarshaller(marshalledObject);
        if (unmarshaller == null) {
            throw new IllegalArgumentException("No unmarshaller for " + marshalledObject);
        }

        return unmarshaller.unmarshall(marshalledObject);
    }

    private static String extractAttributeValueValue(Attribute attribute) {
        for (int i = 0; i < attribute.getAttributeValues().size(); i++) {
            if (attribute.getAttributeValues().get(i) instanceof XSString) {
                XSString str = (XSString) attribute.getAttributeValues().get(i);

                if (AttributeValue.DEFAULT_ELEMENT_LOCAL_NAME.equals(str.getElementQName().getLocalPart()) &&
                        SAMLConstants.SAML20_NS.equals(str.getElementQName().getNamespaceURI())) {

                    return str.getValue();
                }
            }
            else {
                XSAny ep = (XSAny) attribute.getAttributeValues().get(i);
                if (AttributeValue.DEFAULT_ELEMENT_LOCAL_NAME.equals(ep.getElementQName().getLocalPart()) &&
                        SAMLConstants.SAML20_NS.equals(ep.getElementQName().getNamespaceURI())) {

                    if (ep.getUnknownXMLObjects().size() > 0) {
                        StringBuilder res = new StringBuilder();

                        for (XMLObject obj : ep.getUnknownXMLObjects()) {
                            try {
                                res.append(SerializeSupport.nodeToString(marshallObject(obj)));
                            }
                            catch (MarshallingException ex) {
                                log.debug("Failed to marshall attribute - ignoring attribute", ex);
                            }
                        }

                        return res.toString();
                    }

                    return ep.getTextContent();
                }
            }
        }

        return null;
    }

    private static XMLObjectProviderRegistry getProviderRegistry() {
        XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
        if (registry == null) {
            throw new XMLRuntimeException("XMLObjectProviderRegistry was not available from the ConfigurationService");
        }

        return registry;
    }

    private static Marshaller getMarshaller(XMLObject xmlObject) {
        return getProviderRegistry().getMarshallerFactory().getMarshaller(xmlObject);
    }

    private static Unmarshaller getUnmarshaller(Element marshalledObject) {
        return getProviderRegistry().getUnmarshallerFactory().getUnmarshaller(marshalledObject);
    }
}
