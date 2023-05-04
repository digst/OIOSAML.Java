package dk.gov.oio.saml.extensions.appswitch;

import dk.gov.oio.saml.util.Constants;
import org.opensaml.saml.common.SAMLObject;

import javax.xml.namespace.QName;

public interface AppSwitch extends SAMLObject {
    /** Element local name. */
    public static final String DEFAULT_ELEMENT_LOCAL_NAME = "AppSwitch";

    /** Default element name. */
    public static final QName DEFAULT_ELEMENT_NAME = new QName(Constants.NL_EXTENSIONS_PUBLIC_NAMESPACE, DEFAULT_ELEMENT_LOCAL_NAME, Constants.NL_EXTENSIONS_PUBLIC_NAMESPACE_PREFIX);

    /** Local name of the XSI type. */
    public static final String TYPE_LOCAL_NAME = "AppSwitchType";

    /** QName of the XSI type. */
    public static final QName TYPE_NAME = new QName(Constants.NL_EXTENSIONS_PUBLIC_NAMESPACE, TYPE_LOCAL_NAME, Constants.NL_EXTENSIONS_PUBLIC_NAMESPACE_PREFIX);


    public Platform getPlatform();
    public void setPlatform(Platform platform);

    public ReturnURL getReturnURL();
    public void setReturnURL(ReturnURL returnURL);
}

