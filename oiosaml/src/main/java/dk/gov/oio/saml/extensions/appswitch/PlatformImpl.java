package dk.gov.oio.saml.extensions.appswitch;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.common.AbstractSAMLObject;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.List;

public class PlatformImpl extends AbstractSAMLObject implements Platform {
    private AppSwitchPlatform platform;

    protected PlatformImpl(@Nullable String namespaceURI, @Nonnull String elementLocalName, @Nullable String namespacePrefix) {
        super(namespaceURI, elementLocalName, namespacePrefix);
    }

    @Override
    public AppSwitchPlatform getValue() {
        return this.platform;

    }

    @Override
    public void setValue(AppSwitchPlatform newValue) {
        this.platform = this.prepareForAssignment(this.platform, newValue);
    }

    @Nullable
    @Override
    public List<XMLObject> getOrderedChildren() {
        return null;
    }
}
