package dk.gov.oio.saml.extensions.appswitch;

import dk.gov.oio.saml.util.Constants;
import org.opensaml.saml.common.AbstractSAMLObjectBuilder;

public class PlatformBuilder extends AbstractSAMLObjectBuilder<Platform> {
    public PlatformBuilder() {
    }

    public Platform buildObject() {
        return this.buildObject(Constants.NL_EXTENSIONS_PUBLIC_NAMESPACE, Platform.DEFAULT_ELEMENT_LOCAL_NAME, Constants.NL_EXTENSIONS_PUBLIC_NAMESPACE_PREFIX);
    }

    public Platform buildObject(String namespaceURI, String localName, String namespacePrefix) {
        return new PlatformImpl(namespaceURI, localName, namespacePrefix);
    }
}
