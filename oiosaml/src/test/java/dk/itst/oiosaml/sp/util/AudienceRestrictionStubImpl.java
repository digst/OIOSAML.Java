package dk.itst.oiosaml.sp.util;

import java.util.List;

import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;

public class AudienceRestrictionStubImpl extends AbstractStub implements AudienceRestriction {

	private List<Audience> audiences;

	public AudienceRestrictionStubImpl() {
	}
	public AudienceRestrictionStubImpl(List<Audience> arg0) {
		audiences = arg0;
	}
	
	public List<Audience> getAudiences() {
		return audiences;
	}

	
}
