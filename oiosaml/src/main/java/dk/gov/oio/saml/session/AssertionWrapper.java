package dk.gov.oio.saml.session;

import java.io.Serializable;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.joda.time.DateTime;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.saml2.core.impl.AssertionMarshaller;
import org.w3c.dom.Element;

import dk.gov.oio.saml.model.NSISLevel;
import dk.gov.oio.saml.oiobpp.OIOBPPUtil;
import dk.gov.oio.saml.oiobpp.PrivilegeList;
import dk.gov.oio.saml.util.Constants;
import dk.gov.oio.saml.util.InternalException;
import dk.gov.oio.saml.util.SamlHelper;

public class AssertionWrapper implements Serializable {
	private static final long serialVersionUID = -338227958970338958L;
	private String assertion;
	private String id;
	private String issuer;
	private String sessionIndex;
	private NSISLevel nsisLevel;
	private String assuranceLevel;
	private String subjectNameId;
	private List<String> audiences;
	private String authnContextClassRef;
	private PrivilegeList privilegeList;
	private Map<String, String> attributeValues;
	private boolean sessionExpired;
	private DateTime confirmationTime;
	private DateTime conditionTimeNotBefore;
	private DateTime conditionTimeNotOnOrAfter;

	public AssertionWrapper(Assertion assertion) throws InternalException {
		// getAssertion()
		AssertionMarshaller marshaller = new AssertionMarshaller();
		try {
			Element element = marshaller.marshall(assertion);
			this.assertion = elementToString(element);
		}
		catch (MarshallingException e) {
			throw new InternalException(e);
		}

		// getAttributeValues()
		List<AttributeStatement> attributeStatements = assertion.getAttributeStatements();
		if (attributeStatements != null && attributeStatements.size() == 1) {
			AttributeStatement attributeStatement = attributeStatements.get(0);
			this.attributeValues = SamlHelper.extractAttributeValues(attributeStatement);
		}

		// getNSISLevel()
		NSISLevel level = NSISLevel.NONE;
		if (attributeValues != null) {
			String value = attributeValues.get(Constants.LOA);
			level = NSISLevel.getNSISLevelFromAttributeValue(value, NSISLevel.NONE);
			this.assuranceLevel = attributeValues.get(Constants.ASSURANCE_LEVEL); // NULL is acceptable
		}
		this.nsisLevel = level;

		// getIssuer()
		Issuer issuerObj = assertion.getIssuer();
		this.issuer = issuerObj != null ? issuerObj.getValue() : null;

		// getSubjectNameID()
		Subject subject = assertion.getSubject();
		if (subject != null && subject.getNameID() != null) {
			subjectNameId = subject.getNameID().getValue();
		}

		Conditions conditions = assertion.getConditions();
		if (conditions != null) {
			// getAudience()
			List<String> audiences = new ArrayList<>();
			for (AudienceRestriction audienceRestriction : conditions.getAudienceRestrictions()) {
				for (Audience audience : audienceRestriction.getAudiences()) {
					audiences.add(audience.getAudienceURI());
				}
			}

			this.audiences = audiences;

			// getConditionTimeNotOnOrAfter()
			this.conditionTimeNotOnOrAfter = conditions.getNotOnOrAfter();

			// getConditionTimeNotBefore()
			this.conditionTimeNotBefore = conditions.getNotBefore();
		}

		// getConfirmationTime()
		if (assertion.getSubject() != null && assertion.getSubject().getSubjectConfirmations() != null && !assertion.getSubject().getSubjectConfirmations().isEmpty()) {

			for (SubjectConfirmation subjectConfirmation : assertion.getSubject().getSubjectConfirmations()) {
				SubjectConfirmationData data = subjectConfirmation.getSubjectConfirmationData();
				if (data != null && data.getNotOnOrAfter() != null) {
					this.confirmationTime = data.getNotOnOrAfter();
				}
			}
		}

		if (assertion.getAuthnStatements() != null) {
			if (assertion.getAuthnStatements().size() > 0) {
				// We only look into the first AuthnStatement
				AuthnStatement authnStatement = assertion.getAuthnStatements().get(0);

				// getSessionIndex()
				this.sessionIndex = authnStatement.getSessionIndex();

				// isSessionExpired()
				boolean sessionExpired = false;
				if (authnStatement.getSessionNotOnOrAfter() != null) {
					sessionExpired = authnStatement.getSessionNotOnOrAfter().isBeforeNow();
				}
				else {
					sessionExpired = false;
				}
				this.sessionExpired = sessionExpired;

				// getAuthnContextClassRef()
				AuthnContext authnContext = authnStatement.getAuthnContext();
				if (authnContext != null) {
					AuthnContextClassRef authnContextClassRef = authnContext.getAuthnContextClassRef();
					if (authnContextClassRef != null) {
						this.authnContextClassRef = authnContextClassRef.getAuthnContextClassRef();
					}
				}
			}
		}

		// getPrivilegeList()
		if (attributeValues != null) {
			String attributeValue = attributeValues.get(Constants.PRIVILEGE_ATTRIBUTE);
			if (attributeValue != null) {
				this.privilegeList = OIOBPPUtil.parse(attributeValue);
			}
		}

		// getID()
		this.id = assertion.getID();
	}

	private static String elementToString(Element element) {
		try {
			Source source = new DOMSource(element);
			TransformerFactory transFactory = TransformerFactory.newInstance();
			Transformer transformer = transFactory.newTransformer();
			StringWriter buffer = new StringWriter();

			transformer.setOutputProperty(OutputKeys.METHOD, "xml");
			transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
			transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
			transformer.setOutputProperty(OutputKeys.INDENT, "yes");
			transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
			transformer.transform(source, new StreamResult(buffer));

			return buffer.toString();
		}
		catch (Exception ex) {
			return null;
		}
	}

	public String getAssertion() {
		return assertion;
	}
	
	public String getAssertionAsHtml() {
		return htmlEscape(assertion);
	}
	
	private static String htmlEscape(String input) {
		StringBuilder escaped = new StringBuilder();
		for (int i = 0; i < input.length(); i++) {
			char c = input.charAt(i);

			switch (c) {
				case '<':
					escaped.append("&lt;");
					break;
				case '>':
					escaped.append("&gt;");
					break;
				case '"':
					escaped.append("&quot;");
					break;
				case '&':
					escaped.append("&amp;");
					break;
				case '\'':
					escaped.append("&#39;");
					break;
				default:
					escaped.append(c);
					break;
			}
		}

		return escaped.toString();
	}
	
	public NSISLevel getNsisLevel() {
		return nsisLevel;
	}

	public String getAssuranceLevel() {
		return assuranceLevel;
	}

	public String getID() {
		return id;
	}

	public String getIssuer() {
		return issuer;
	}

	public String getSessionIndex() {
		return sessionIndex;
	}

	public String getSubjectNameId() {
		return subjectNameId;
	}

	public List<String> getAudiences() {
		return audiences;
	}

	public String getAuthnContextClassRef() {
		return authnContextClassRef;
	}

	public PrivilegeList getPrivilegeList() {
		return privilegeList;
	}

	public Map<String, String> getAttributeValues() {
		return attributeValues;
	}

	public boolean isSessionExpired() {
		return sessionExpired;
	}

	public DateTime getConfirmationTime() {
		return confirmationTime;
	}

	public DateTime getConditionTimeNotBefore() {
		return conditionTimeNotBefore;
	}

	public DateTime getConditionTimeNotOnOrAfter() {
		return conditionTimeNotOnOrAfter;
	}
}
