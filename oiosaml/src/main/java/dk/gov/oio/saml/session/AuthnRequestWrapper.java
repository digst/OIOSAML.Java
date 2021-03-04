package dk.gov.oio.saml.session;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import dk.gov.oio.saml.model.NSISLevel;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnRequest;

import dk.gov.oio.saml.util.InternalException;

public class AuthnRequestWrapper implements Serializable {
	private static final long serialVersionUID = -6155927753076931485L;
	private String id;
	private boolean forceAuthn;
	private boolean passive;
	private NSISLevel requestedNsisLevel;
	private List<String> authnContextClassRefValues;

	public AuthnRequestWrapper(AuthnRequest authnRequest, NSISLevel requestedNsisLevel) throws InternalException {
		// get ContextClassRefs
		authnContextClassRefValues = new ArrayList<String>();
        if (authnRequest.getRequestedAuthnContext() != null) {
            List<AuthnContextClassRef> authnContextClassRefs = authnRequest.getRequestedAuthnContext().getAuthnContextClassRefs();

            for (AuthnContextClassRef authnContextClassRef : authnContextClassRefs) {
                String value = authnContextClassRef.getAuthnContextClassRef();
                if (value != null && value.length() > 0) {
                	getAuthnContextClassRefValues().add(value);
                }
            }
        }
        
        // get passive/forceAuthn
        passive = authnRequest.isPassive();
        forceAuthn = authnRequest.isForceAuthn();
        this.requestedNsisLevel = requestedNsisLevel;

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
}
