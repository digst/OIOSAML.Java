package dk.gov.oio.saml.extensions.appswitch;

import dk.gov.oio.saml.util.Constants;
import org.opensaml.saml.common.AbstractSAMLObjectBuilder;

public class ReturnURLBuilder extends AbstractSAMLObjectBuilder<ReturnURL> {
    public ReturnURLBuilder() {
    }

    public ReturnURL buildObject() {
        return this.buildObject(Constants.NL_EXTENSIONS_PUBLIC_NAMESPACE, ReturnURL.DEFAULT_ELEMENT_LOCAL_NAME, Constants.NL_EXTENSIONS_PUBLIC_NAMESPACE_PREFIX);
    }

    public ReturnURL buildObject(String namespaceURI, String localName, String namespacePrefix) {
        return new ReturnURLImpl(namespaceURI, localName, namespacePrefix);
    }
}

