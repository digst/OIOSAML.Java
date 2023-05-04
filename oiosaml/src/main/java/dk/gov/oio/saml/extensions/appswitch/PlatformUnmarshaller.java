package dk.gov.oio.saml.extensions.appswitch;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.common.AbstractSAMLObjectUnmarshaller;

public class PlatformUnmarshaller extends AbstractSAMLObjectUnmarshaller {
    protected void processElementContent(final XMLObject samlObject, final AppSwitchPlatform elementContent) {
        final Platform platform = (Platform) samlObject;
        platform.setValue(elementContent);
    }
}

