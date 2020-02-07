package dk.itst.oiosaml.sp.util;

import org.opensaml.saml2.core.Audience;

public class AudienceStubImpl extends AbstractStub implements Audience {

	private String audienceURI;

	public AudienceStubImpl() {
	}
	
	public String getAudienceURI() {
		return audienceURI;
	}

	
	public void setAudienceURI(String arg0) {
		audienceURI = arg0;
	}

	
}
