package dk.gov.oio.saml.extensions.appswitch;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.common.AbstractSAMLObject;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.List;

public class ReturnURLImpl extends AbstractSAMLObject implements ReturnURL {
    private String returnURL;

    protected ReturnURLImpl(@Nullable String namespaceURI, @Nonnull String elementLocalName, @Nullable String namespacePrefix) {
        super(namespaceURI, elementLocalName, namespacePrefix);
    }

    @Override
    public String getValue() {
        return this.returnURL;
    }

    @Override
    public void setValue(String newValue) {
        this.returnURL = this.prepareForAssignment(this.returnURL, newValue);
    }

    @Nullable
    @Override
    public List<XMLObject> getOrderedChildren() {
        return null;
    }
}


