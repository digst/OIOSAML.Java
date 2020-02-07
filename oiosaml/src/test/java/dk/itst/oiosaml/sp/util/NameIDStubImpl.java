package dk.itst.oiosaml.sp.util;

import org.opensaml.saml2.core.NameID;

public class NameIDStubImpl extends AbstractStub implements NameID {

	private String value;

	public NameIDStubImpl() {
	}
	
	
	public String getFormat() {
		return null;
	}

	
	public String getNameQualifier() {
		return null;
	}

	
	public String getSPNameQualifier() {
		return null;
	}

	
	public String getSPProvidedID() {
		return null;
	}

	
	public String getValue() {
		return this.value;
	}

	
	public void setFormat(String arg0) {

	}

	
	public void setNameQualifier(String arg0) {

	}

	
	public void setSPNameQualifier(String arg0) {

	}

	
	public void setSPProvidedID(String arg0) {

	}

	
	public void setValue(String arg0) {
		this.value = arg0;
	}

}
