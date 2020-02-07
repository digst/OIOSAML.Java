package dk.itst.oiosaml.sp.util;

import org.opensaml.saml2.core.AuthnContextClassRef;

public class AuthnContextClassRefStubImpl extends AbstractStub implements AuthnContextClassRef {

	private String authnContextClassRef;

	public AuthnContextClassRefStubImpl() {
	}
	
	public String getAuthnContextClassRef() {
		return authnContextClassRef;
	}

	
	public void setAuthnContextClassRef(String arg0) {
		authnContextClassRef = arg0;
	}
}
