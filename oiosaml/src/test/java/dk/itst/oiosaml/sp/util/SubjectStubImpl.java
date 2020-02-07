package dk.itst.oiosaml.sp.util;

import java.util.List;

import org.opensaml.saml2.core.BaseID;
import org.opensaml.saml2.core.EncryptedID;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;

public class SubjectStubImpl extends AbstractStub implements Subject {
	
	private NameID nameID;
	private List<SubjectConfirmation> subjectConfirmations;

	public SubjectStubImpl() {
	}
	
	public SubjectStubImpl(List<SubjectConfirmation> arg0) {
		subjectConfirmations = arg0;
	}
	
	
	public BaseID getBaseID() {

		return null;
	}

	
	public EncryptedID getEncryptedID() {

		return null;
	}

	
	public NameID getNameID() {
		return this.nameID;
	}

	
	public List<SubjectConfirmation> getSubjectConfirmations() {
		return subjectConfirmations;
	}

	
	public void setBaseID(BaseID arg0) {


	}

	
	public void setEncryptedID(EncryptedID arg0) {


	}

	
	public void setNameID(NameID arg0) {
		this.nameID = arg0;
	}
}
