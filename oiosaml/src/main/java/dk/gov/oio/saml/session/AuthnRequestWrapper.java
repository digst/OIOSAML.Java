package dk.gov.oio.saml.session;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import dk.gov.oio.saml.model.NSISLevel;
import dk.gov.oio.saml.util.StringUtil;
import org.joda.time.DateTime;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnRequest;

import dk.gov.oio.saml.util.InternalException;
import org.opensaml.saml.saml2.core.Issuer;

public class AuthnRequestWrapper implements Serializable {
    private static final long serialVersionUID = -6155927753076931485L;
    private String id;
    private boolean forceAuthn;
    private boolean passive;
    private NSISLevel requestedNsisLevel;
    private List<String> authnContextClassRefValues;
    private String issuer;
    private String issueInstant;
    private String destination;
    private String authnRequestAsBase64;

    public AuthnRequestWrapper(AuthnRequest authnRequest, NSISLevel requestedNsisLevel) throws InternalException {
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
        this.destination = authnRequest.getDestination();

        Issuer issuer = authnRequest.getIssuer();
        this.issuer = (issuer != null) ? issuer.getValue() : "";

        DateTime issueInstant = authnRequest.getIssueInstant();
        this.issueInstant = (issueInstant != null) ? issueInstant.toString() : "";

        // get id
        this.id = authnRequest.getID();
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

    public String getAuthnRequestAsBase64() {
        return authnRequestAsBase64;
    }
}
