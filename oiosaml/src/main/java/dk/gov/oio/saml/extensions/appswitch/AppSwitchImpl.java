package dk.gov.oio.saml.extensions.appswitch;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.common.AbstractSAMLObject;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class AppSwitchImpl extends AbstractSAMLObject implements AppSwitch {
    private Platform platform;
    private ReturnURL returnURL;

    protected AppSwitchImpl(@Nullable String namespaceURI, @Nonnull String elementLocalName, @Nullable String namespacePrefix) {
        super(namespaceURI, elementLocalName, namespacePrefix);
    }

    @Override
    public Platform getPlatform() {
        return platform;
    }

    @Override
    public ReturnURL getReturnURL() {
        return returnURL;
    }

    @Override
    public void setPlatform(Platform platform) {
        this.platform = platform;
    }

    @Override
    public void setReturnURL(ReturnURL returnURL) {
        this.returnURL = returnURL;
    }

    @Nullable
    @Override
    public List<XMLObject> getOrderedChildren() {
        ArrayList<XMLObject> children = new ArrayList<>();
        children.add(this.platform);
        children.add(this.returnURL);

        return Collections.unmodifiableList(children);
    }
}

