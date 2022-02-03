package dk.gov.oio.saml.session;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import dk.gov.oio.saml.util.StringUtil;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import dk.gov.oio.saml.model.NSISLevel;
import dk.gov.oio.saml.oiobpp.OIOBPPUtil;
import dk.gov.oio.saml.oiobpp.PrivilegeList;
import dk.gov.oio.saml.util.Constants;
import dk.gov.oio.saml.util.InternalException;
import dk.gov.oio.saml.util.SamlHelper;

public class AssertionWrapper implements Serializable {
    private static final Logger log = LoggerFactory.getLogger(AssertionWrapper.class);
    private static final long serialVersionUID = -4561395634523843337L;

    private String id;
    private String assertionString;
    private String assertionBase64;
    private String sessionIndex;
    private String issuer;
    private String subjectNameId;
    private String subjectNameIdFormat;
    private String signingCredentialEntityId;
    private List<String> audiences;
    private String authnContextClassRef;
    private PrivilegeList privilegeList;
    private Map<String, String> attributeValues;
    private boolean sessionExpired;
    private DateTime confirmationTime;
    private DateTime conditionTimeNotBefore;
    private DateTime conditionTimeNotOnOrAfter;

    public AssertionWrapper(Assertion assertion) throws InternalException {
        this.assertionBase64 = StringUtil.xmlObjectToBase64(assertion);

        // getAssertionAsString()
        AssertionMarshaller marshaller = new AssertionMarshaller();
        try {
            Element element = marshaller.marshall(assertion);
            this.assertionString = StringUtil.elementToString(element);
        }
        catch (MarshallingException e) {
            throw new InternalException(e);
        }

        // getIssuer()
        Issuer issuerObj = assertion.getIssuer();
        this.issuer = issuerObj != null ? issuerObj.getValue() : null;

        // getSubjectNameID()
        Subject subject = assertion.getSubject();
        if (subject != null && subject.getNameID() != null) {
            subjectNameId = subject.getNameID().getValue();
            subjectNameIdFormat = subject.getNameID().getFormat();
        }

        // getAttributeValues()
        List<AttributeStatement> attributeStatements = assertion.getAttributeStatements();
        if (attributeStatements != null && attributeStatements.size() == 1) {
            AttributeStatement attributeStatement = attributeStatements.get(0);
            this.attributeValues = SamlHelper.extractAttributeValues(attributeStatement);
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
                // getSessionIndex()
                for (AuthnStatement authnStatement : assertion.getAuthnStatements()) {
                    if (StringUtil.isNotEmpty(authnStatement.getSessionIndex())) {
                        this.sessionIndex = authnStatement.getSessionIndex();
                    }
                }

                // We only look into the first AuthnStatement
                AuthnStatement authnStatement = assertion.getAuthnStatements().get(0);

                // isSessionExpired()
                boolean sessionExpired = false;
                if (authnStatement.getSessionNotOnOrAfter() != null) {
                    sessionExpired = authnStatement.getSessionNotOnOrAfter().isBeforeNow();
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

        // getSigningCredentialEntityId()
        if (null != assertion.getSignature() && null != assertion.getSignature().getSigningCredential()) {
            this.signingCredentialEntityId = assertion.getSignature().getSigningCredential().getEntityId();
        }

        // getID()
        this.id = assertion.getID();
    }

    public String getAssertionAsString() {
        return assertionString;
    }

    public String getAssertionAsBase64() {
        return assertionBase64;
    }
    
    public String getAssertionAsHtml() {
        return htmlEscape(assertionString);
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
        if (attributeValues != null) {
            String value = attributeValues.get(Constants.LOA);
            return NSISLevel.getNSISLevelFromAttributeValue(value, NSISLevel.NONE);
        }
        return NSISLevel.NONE;
    }

    public String getAssuranceLevel() {
        if (attributeValues != null) {
            return attributeValues.get(Constants.ASSURANCE_LEVEL); // NULL is acceptable
        }
        return null;
    }

    public String getID() {
        return this.id;
    }

    public String getIssuer() {
        return this.issuer;
    }

    public String getSessionIndex() {
        return sessionIndex;
    }

    public String getSubjectNameId() {
        return subjectNameId;
    }

    public String getSubjectNameIdFormat() {
        return subjectNameIdFormat;
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

    public String getSigningCredentialEntityId() {
        return signingCredentialEntityId;
    }

    public boolean isReplayOf(AssertionWrapper assertionWrapper) {
        if (null == assertionWrapper) {
            return false;
        }
        if (StringUtil.isEmpty(assertionWrapper.getID()) || StringUtil.isEmpty(assertionWrapper.getSessionIndex())) {
            return false;
        }
        return assertionWrapper.getSessionIndex().equals(this.getSessionIndex())
                && assertionWrapper.getID().equals(this.getID());
    }


    @Override
    public String toString() {
        return String.format("AssertionWrapper{assertion='%s'}", assertionString);
    }
}
