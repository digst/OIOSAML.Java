package dk.gov.oio.saml.extensions.appswitch;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.common.AbstractSAMLObjectUnmarshaller;

public class AppSwitchUnmarshaller extends AbstractSAMLObjectUnmarshaller {
    protected void processChildElement(final XMLObject parentObject, final XMLObject childObject)
            throws UnmarshallingException {
        final AppSwitch appSwitch = (AppSwitch) parentObject;

        if (childObject instanceof Platform) {
            appSwitch.setPlatform((Platform) childObject);
        } else if (childObject instanceof ReturnURL) {
            appSwitch.setReturnURL((ReturnURL) childObject);
        } else {
            super.processChildElement(parentObject, childObject);
        }
    }
}
