package dk.gov.oio.saml.extensions.appswitch;

import dk.gov.oio.saml.util.Constants;
import org.opensaml.saml.common.SAMLObject;

import javax.xml.namespace.QName;

public interface ReturnURL extends SAMLObject {
    String DEFAULT_ELEMENT_LOCAL_NAME = "ReturnURL";
    QName DEFAULT_ELEMENT_NAME = new QName(Constants.NL_EXTENSIONS_PUBLIC_NAMESPACE, DEFAULT_ELEMENT_LOCAL_NAME, Constants.NL_EXTENSIONS_PUBLIC_NAMESPACE_PREFIX);
    String TYPE_LOCAL_NAME = "string";
    QName TYPE_NAME = new QName("http://www.w3.org/2001/XMLSchema", TYPE_LOCAL_NAME, "xs");
    public String getValue();
    public void setValue(String newValue);
}
