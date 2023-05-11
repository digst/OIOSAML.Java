package dk.gov.oio.saml.extensions.appswitch;

import dk.gov.oio.saml.util.Constants;
import org.opensaml.saml.common.SAMLObject;

import javax.xml.namespace.QName;

public interface Platform extends SAMLObject {
    String DEFAULT_ELEMENT_LOCAL_NAME = "Platform";
    QName DEFAULT_ELEMENT_NAME = new QName(Constants.NL_EXTENSIONS_PUBLIC_NAMESPACE, DEFAULT_ELEMENT_LOCAL_NAME, Constants.NL_EXTENSIONS_PUBLIC_NAMESPACE_PREFIX);
    String TYPE_LOCAL_NAME = "AppSwitchPlatformType";
    QName TYPE_NAME = new QName(Constants.NL_EXTENSIONS_PUBLIC_NAMESPACE, TYPE_LOCAL_NAME, Constants.NL_EXTENSIONS_PUBLIC_NAMESPACE_PREFIX);

    public AppSwitchPlatform getValue();
    public void setValue(AppSwitchPlatform newValue);
}
