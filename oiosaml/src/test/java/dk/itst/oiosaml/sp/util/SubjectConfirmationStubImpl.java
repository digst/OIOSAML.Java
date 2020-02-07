package dk.itst.oiosaml.sp.util;

import org.opensaml.saml2.core.BaseID;
import org.opensaml.saml2.core.EncryptedID;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;

public class SubjectConfirmationStubImpl extends AbstractStub implements SubjectConfirmation {

	private String method;
	private SubjectConfirmationData subjectConfirmationData;

	public SubjectConfirmationStubImpl() {

	}
	
	public BaseID getBaseID() {

		return null;
	}

	
	public EncryptedID getEncryptedID() {

		return null;
	}

	
	public String getMethod() {
		return method;
	}

	
	public NameID getNameID() {

		return null;
	}

	
	public SubjectConfirmationData getSubjectConfirmationData() {
		return subjectConfirmationData;
	}

	
	public void setBaseID(BaseID arg0) {


	}

	
	public void setEncryptedID(EncryptedID arg0) {


	}

	
	public void setMethod(String arg0) {
		this.method = arg0;
	}

	
	public void setNameID(NameID arg0) {


	}

	
	public void setSubjectConfirmationData(SubjectConfirmationData arg0) {
		this.subjectConfirmationData = arg0;
	}

}
