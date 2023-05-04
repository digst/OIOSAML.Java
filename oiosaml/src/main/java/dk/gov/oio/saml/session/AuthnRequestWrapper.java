package dk.gov.oio.saml.session;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import dk.gov.oio.saml.extensions.appswitch.AppSwitch;
import dk.gov.oio.saml.model.NSISLevel;
import dk.gov.oio.saml.util.StringUtil;
import org.joda.time.DateTime;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnRequest;

import dk.gov.oio.saml.util.InternalException;
import org.opensaml.saml.saml2.core.Extensions;
import org.opensaml.saml.saml2.core.Issuer;

public class AuthnRequestWrapper implements Serializable {
    private static final long serialVersionUID = -2647272712207296480L;
    private Extensions extensions;

    private final String id;
    private final boolean forceAuthn;
    private final boolean passive;
    private final NSISLevel requestedNsisLevel;
    private final List<String> authnContextClassRefValues;
    private final String issuer;
    private final String issueInstant;
    private final String destination;
    private final String authnRequestAsBase64;
    private final String requestPath;

    public AuthnRequestWrapper(AuthnRequest authnRequest, NSISLevel requestedNsisLevel, String requestPath) throws InternalException {
        this.authnRequestAsBase64 = StringUtil.xmlObjectToBase64(authnRequest);

        // get ContextClassRefs
        authnContextClassRefValues = new ArrayList<String>();
        if (authnRequest.getRequestedAuthnContext() != null) {
            List<AuthnContextClassRef> authnContextClassRefs = authnRequest.getRequestedAuthnContext().getAuthnContextClassRefs();

            for (AuthnContextClassRef authnContextClassRef : authnContextClassRefs) {
                String value = authnContextClassRef.getAuthnContextClassRef();
                if (StringUtil.isNotEmpty(value)) {
                    getAuthnContextClassRefValues().add(value);
                }
            }
        }
        
        // get passive/forceAuthn
        this.passive = authnRequest.isPassive();
        this.forceAuthn = authnRequest.isForceAuthn();
        this.requestedNsisLevel = requestedNsisLevel;
        this.requestPath = requestPath;
        this.destination = authnRequest.getDestination();

        Issuer issuer = authnRequest.getIssuer();
        this.issuer = (issuer != null) ? issuer.getValue() : "";

        DateTime issueInstant = authnRequest.getIssueInstant();
        this.issueInstant = (issueInstant != null) ? issueInstant.toString() : "";

        // get id
        this.id = authnRequest.getID();
        this.extensions = authnRequest.getExtensions();
    }

    public String getId() {
        return id;
    }

    public List<String> getAuthnContextClassRefValues() {
        return authnContextClassRefValues;
    }

    public boolean isForceAuthn() {
        return forceAuthn;
    }

    public boolean isPassive() {
        return passive;
    }

    public NSISLevel getRequestedNsisLevel() {
        return requestedNsisLevel;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getIssueInstant() {
        return issueInstant;
    }

    public String getDestination() {
        return destination;
    }

    public String getRequestPath() {
        return requestPath;
    }

    public String getAuthnRequestAsBase64() {
        return authnRequestAsBase64;
    }

    public AppSwitch getAppSwitch() {
        return (AppSwitch) this.getExtensionOfType(AppSwitch.class);
    }

    private <TExtension extends XMLObject> Object getExtensionOfType(Class<TExtension> type) {
        if(this.extensions == null)
            return null;

        for (XMLObject extension:extensions.getOrderedChildren()) {
            if(extension instanceof AppSwitch)
                return extension;
        }

        return null;
    }
}
