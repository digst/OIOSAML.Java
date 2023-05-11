package dk.gov.oio.saml.extensions.appswitch;

import net.shibboleth.utilities.java.support.xml.ElementSupport;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.AbstractSAMLObjectMarshaller;
import org.w3c.dom.Element;

public class ReturnURLMarshaller extends AbstractSAMLObjectMarshaller {

    protected void marshallElementContent(final XMLObject samlObject, final Element domElement)
            throws MarshallingException {
        final ReturnURL returnURL = (ReturnURL) samlObject;
        ElementSupport.appendTextContent(domElement, returnURL.getValue());
    }
}

