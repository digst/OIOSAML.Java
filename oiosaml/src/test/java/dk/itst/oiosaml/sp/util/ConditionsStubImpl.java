package dk.itst.oiosaml.sp.util;

import java.util.List;

import org.joda.time.DateTime;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.Condition;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.OneTimeUse;
import org.opensaml.saml2.core.ProxyRestriction;

public class ConditionsStubImpl extends AbstractStub implements Conditions {

	private List<AudienceRestriction> audienceRestrictions;

	public ConditionsStubImpl(List<AudienceRestriction> arg0) {
		audienceRestrictions = arg0;
	}
	
	
	public List<AudienceRestriction> getAudienceRestrictions() {
		return audienceRestrictions;
	}

	
	public List<Condition> getConditions() {

		return null;
	}

	
	public DateTime getNotBefore() {

		return null;
	}

	
	public DateTime getNotOnOrAfter() {

		return null;
	}

	
	public OneTimeUse getOneTimeUse() {

		return null;
	}

	
	public ProxyRestriction getProxyRestriction() {

		return null;
	}

	
	public void setNotBefore(DateTime arg0) {


	}

	
	public void setNotOnOrAfter(DateTime arg0) {


	}
}
