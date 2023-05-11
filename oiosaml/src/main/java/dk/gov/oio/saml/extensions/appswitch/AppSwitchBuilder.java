package dk.gov.oio.saml.extensions.appswitch;

import dk.gov.oio.saml.util.Constants;
import org.opensaml.saml.common.AbstractSAMLObjectBuilder;

public class AppSwitchBuilder extends AbstractSAMLObjectBuilder<AppSwitch> {
    public AppSwitchBuilder() {
    }

    public AppSwitch buildObject() {
        return this.buildObject(Constants.NL_EXTENSIONS_PUBLIC_NAMESPACE, AppSwitch.DEFAULT_ELEMENT_LOCAL_NAME, Constants.NL_EXTENSIONS_PUBLIC_NAMESPACE_PREFIX);
    }

    public AppSwitch buildObject(String namespaceURI, String localName, String namespacePrefix) {
        return new AppSwitchImpl(namespaceURI, localName, namespacePrefix);
    }
}
