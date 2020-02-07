package dk.itst.oiosaml.sp.util;

import org.joda.time.DateTime;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.SubjectLocality;

public class AuthnStatementStubImpl extends AbstractStub implements AuthnStatement {

	private String sessionIndex;
	private DateTime sessionNotOnOrAfter;
	private AuthnContext authnContext;

	public AuthnStatementStubImpl() {
	
	}
	public AuthnContext getAuthnContext() {
		return authnContext;
	}

	public DateTime getAuthnInstant() {

		return null;
	}

	
	public String getSessionIndex() {
		return sessionIndex;
	}

	
	public DateTime getSessionNotOnOrAfter() {
		return sessionNotOnOrAfter;
	}

	
	public SubjectLocality getSubjectLocality() {

		return null;
	}

	
	public void setAuthnContext(AuthnContext arg0) {
		authnContext = arg0;
	}

	
	public void setAuthnInstant(DateTime arg0) {


	}

	
	public void setSessionIndex(String arg0) {
		sessionIndex = arg0;
	}

	
	public void setSessionNotOnOrAfter(DateTime arg0) {
		sessionNotOnOrAfter = arg0;
	}

	
	public void setSubjectLocality(SubjectLocality arg0) {


	}

	
}
