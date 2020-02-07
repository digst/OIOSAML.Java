package dk.itst.oiosaml.sp.util;

import java.util.List;

import org.opensaml.saml2.core.AuthenticatingAuthority;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextDecl;
import org.opensaml.saml2.core.AuthnContextDeclRef;

public class AuthnContextStubImpl extends AbstractStub implements AuthnContext {
	
	private AuthnContextClassRef authnContextClassRef;

	public AuthnContextStubImpl() {
	}
	
	public AuthnContextDecl getAuthContextDecl() {

		return null;
	}

	
	public List<AuthenticatingAuthority> getAuthenticatingAuthorities() {

		return null;
	}

	
	public AuthnContextClassRef getAuthnContextClassRef() {
		return authnContextClassRef;
	}

	
	public AuthnContextDeclRef getAuthnContextDeclRef() {

		return null;
	}

	
	public void setAuthnContextClassRef(AuthnContextClassRef arg0) {
		authnContextClassRef = arg0;
	}

	
	public void setAuthnContextDecl(AuthnContextDecl arg0) {


	}

	
	public void setAuthnContextDeclRef(AuthnContextDeclRef arg0) {


	}
}
