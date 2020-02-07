package dk.itst.oiosaml.sp.util;

import java.util.List;

import javax.xml.namespace.QName;

import org.joda.time.DateTime;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Advice;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.AuthzDecisionStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Statement;
import org.opensaml.saml2.core.Subject;
import org.opensaml.xml.signature.Signature;

public class AssertionStubImpl extends AbstractStub implements Assertion {

	private Subject subject;
	private Conditions conditions;
	private List<AuthnStatement> authnStatements;

	public AssertionStubImpl() {
	}
	
	public AssertionStubImpl(List<AuthnStatement> arg0) {
		authnStatements = arg0;
	}
	
	
	public Advice getAdvice() {

		return null;
	}

	
	public List<AttributeStatement> getAttributeStatements() {

		return null;
	}

	
	public List<AuthnStatement> getAuthnStatements() {
		return authnStatements;
	}

	
	public List<AuthzDecisionStatement> getAuthzDecisionStatements() {

		return null;
	}

	
	public Conditions getConditions() {
		return conditions;
	}

	
	public String getID() {

		return null;
	}

	
	public DateTime getIssueInstant() {

		return null;
	}

	
	public Issuer getIssuer() {

		return null;
	}

	
	public List<Statement> getStatements() {

		return null;
	}

	
	public List<Statement> getStatements(QName arg0) {

		return null;
	}

	
	public Subject getSubject() {
		return this.subject;
	}

	
	public SAMLVersion getVersion() {

		return null;
	}

	
	public void setAdvice(Advice arg0) {


	}

	
	public void setConditions(Conditions arg0) {
		conditions = arg0;
	}

	
	public void setID(String arg0) {


	}

	
	public void setIssueInstant(DateTime arg0) {


	}

	
	public void setIssuer(Issuer arg0) {


	}

	
	public void setSubject(Subject arg0) {
		this.subject = arg0;
	}

	
	public void setVersion(SAMLVersion arg0) {


	}

	
	public String getSignatureReferenceID() {

		return null;
	}

	
	public Signature getSignature() {

		return null;
	}

	
	public boolean isSigned() {

		return false;
	}

	
	public void setSignature(Signature arg0) {


	}

	

}
