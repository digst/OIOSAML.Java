package dk.gov.oio.saml.extensions.appswitch;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.common.AbstractSAMLObjectUnmarshaller;

public class ReturnURLUnmarshaller extends AbstractSAMLObjectUnmarshaller {
    protected void processElementContent(final XMLObject samlObject, final String elementContent) {
        final ReturnURL returnURL = (ReturnURL) samlObject;
        returnURL.setValue(elementContent);
    }
}

