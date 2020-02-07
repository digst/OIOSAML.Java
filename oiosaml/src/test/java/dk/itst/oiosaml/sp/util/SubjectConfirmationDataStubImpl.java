package dk.itst.oiosaml.sp.util;

import java.util.List;

import javax.xml.namespace.QName;

import org.joda.time.DateTime;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.util.AttributeMap;

public class SubjectConfirmationDataStubImpl extends AbstractStub implements SubjectConfirmationData {

	private String recipient;
	private DateTime notOnOrAfter;

	
	public String getAddress() {

		return null;
	}

	
	public String getInResponseTo() {

		return null;
	}

	
	public DateTime getNotBefore() {

		return null;
	}

	
	public DateTime getNotOnOrAfter() {
		return notOnOrAfter;
	}

	
	public String getRecipient() {
		return recipient;
	}

	
	public void setAddress(String arg0) {


	}

	
	public void setInResponseTo(String arg0) {


	}

	
	public void setNotBefore(DateTime arg0) {


	}

	
	public void setNotOnOrAfter(DateTime arg0) {
		notOnOrAfter = arg0;
	}

	
	public void setRecipient(String arg0) {
		recipient = arg0;

	}


	public List<XMLObject> getUnknownXMLObjects() {
		return null;
	}


	public List<XMLObject> getUnknownXMLObjects(QName arg0) {
		return null;
	}


	public AttributeMap getUnknownAttributes() {
		return null;
	}
}
