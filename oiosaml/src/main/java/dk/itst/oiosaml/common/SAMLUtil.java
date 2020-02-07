/*
 * The contents of this file are subject to the Mozilla Public 
 * License Version 1.1 (the "License"); you may not use this 
 * file except in compliance with the License. You may obtain 
 * a copy of the License at http://www.mozilla.org/MPL/
 * 
 * Software distributed under the License is distributed on an 
 * "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, either express 
 * or implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 *
 * The Original Code is OIOSAML Java Service Provider.
 * 
 * The Initial Developer of the Original Code is Trifork A/S. Portions 
 * created by Trifork A/S are Copyright (C) 2008 Danish National IT 
 * and Telecom Agency (http://www.itst.dk). All Rights Reserved.
 * 
 * Contributor(s):
 *   Joakim Recht <jre@trifork.com>
 *   Rolf Njor Jensen <rolf@trifork.com>
 *
 */
package dk.itst.oiosaml.common;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.security.InvalidParameterException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Artifact;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.core.SessionIndex;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.metadata.ArtifactResolutionService;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.AttributeConsumingService;
import org.opensaml.saml2.metadata.Company;
import org.opensaml.saml2.metadata.EmailAddress;
import org.opensaml.saml2.metadata.GivenName;
import org.opensaml.saml2.metadata.LocalizedString;
import org.opensaml.saml2.metadata.NameIDFormat;
import org.opensaml.saml2.metadata.Organization;
import org.opensaml.saml2.metadata.OrganizationDisplayName;
import org.opensaml.saml2.metadata.OrganizationName;
import org.opensaml.saml2.metadata.OrganizationURL;
import org.opensaml.saml2.metadata.RequestedAttribute;
import org.opensaml.saml2.metadata.ServiceName;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml2.metadata.SurName;
import org.opensaml.saml2.metadata.TelephoneNumber;
import org.opensaml.xml.ElementExtensibleXMLObject;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.KeyName;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import dk.itst.oiosaml.error.Layer;
import dk.itst.oiosaml.error.WrappedException;
import dk.itst.oiosaml.logging.Logger;
import dk.itst.oiosaml.logging.LoggerFactory;

/**
 * Class with utility methods for creating SAML objects.
 * 
 * Before accessing any of the methods in this class, {@link DefaultBootstrap#bootstrap()} 
 * must have been run at some point. If this has not been done, a {@link NullPointerException}
 * will happen inside OpenSAML.
 * 
 */
public class SAMLUtil {
	public static final String VERSION = "$Id: BRSUtil.java 2910 2008-05-21 13:07:31Z jre $";
	private static final Logger log = LoggerFactory.getLogger(SAMLUtil.class);
	public static final String OIOSAML_HOME = "oiosaml.home";
    public static final String OIOSAML_DEFAULT_CONFIGURATION_FILE = "oiosaml-sp.properties";
	
	private static final Map<Class<?>, QName> elementCache = new ConcurrentHashMap<Class<?>, QName>();

	/**
	 * Build a new empty object of the requested type.
	 * 
	 * The requested type must have a DEFAULT_ELEMENT_NAME attribute describing the element type as a QName.
	 * 
	 * @param <T> SAML Object type
	 */
	@SuppressWarnings("unchecked")
	public static <T extends XMLObject> T buildXMLObject(Class<T> type) {
		try {
			QName objectQName = getElementQName(type);
			XMLObjectBuilder<T> builder = Configuration.getBuilderFactory().getBuilder(objectQName);
			if (builder == null) {
				throw new InvalidParameterException("No builder exists for object: " + objectQName.getLocalPart());
			}
			return builder.buildObject(objectQName.getNamespaceURI(), objectQName.getLocalPart(), objectQName.getPrefix());
		} catch (SecurityException e) {
			throw new RuntimeException(e);
		}				
	}

	private static <T> QName getElementQName(Class<T> type) {
		if (elementCache.containsKey(type)) return elementCache.get(type);
		
		try {
			Field typeField;
			try { 
				typeField = type.getDeclaredField("DEFAULT_ELEMENT_NAME");
			} catch (NoSuchFieldException ex) {
				typeField = type.getDeclaredField("ELEMENT_NAME");
			}

			QName objectQName = (QName) typeField.get(null);
			elementCache.put(type, objectQName);
			return objectQName;
		} catch (NoSuchFieldException e) {
			throw new RuntimeException(e);
		} catch (IllegalAccessException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Create an issuer with a given value.
	 * 
	 * @param value
	 *            The value
	 * @return The SAML Issuer with the given value
	 */
	public static Issuer createIssuer(String value) {
		if (value == null) return null;
		
		Issuer issuer = buildXMLObject(Issuer.class);
		issuer.setValue(value);
		return issuer;
	}

	/**
	 * Create a NameID with a given value.
	 * 
	 * @param nameIDValue
	 *            The value of the nameID
	 * @return The SAML NameId with the given nameId
	 */
	public static NameID createNameID(String nameIDValue) {
		NameID nameID = buildXMLObject(NameID.class);
		nameID.setValue(nameIDValue);
		nameID.setFormat(OIOSAMLConstants.PERSISTENT);
		return nameID;
	}

	/**
	 * Create a SessionIndex with a given value.
	 * 
	 * @param value
	 *            The value of the nameID
	 * @return The SAML SessionIndex with the given value
	 */
	public static SessionIndex createSessionIndex(String value) {
		SessionIndex sessionIndex = buildXMLObject(SessionIndex.class);
		sessionIndex.setSessionIndex(value);
		return sessionIndex;
	}

	/**
	 * Create a subject with a given nameID value.
	 * 
	 * The subject is given a confirmation with method bearer.
	 * 
	 * @param nameIDValue
	 *            The value of the nameID
	 * @return The SAML subject with the given nameId
	 */
	public static Subject createSubject(String nameIDValue,
			String recipient, DateTime notOnOrAfter) {
		Subject subject = buildXMLObject(Subject.class);
		subject.setNameID(createNameID(nameIDValue));
		SubjectConfirmation subjectConfirmation = buildXMLObject(SubjectConfirmation.class);
		subjectConfirmation.setMethod(OIOSAMLConstants.METHOD_BEARER);
		SubjectConfirmationData subjectConfirmationData = buildXMLObject(SubjectConfirmationData.class);
		subjectConfirmationData.setRecipient(recipient);
		subjectConfirmationData.setNotOnOrAfter(notOnOrAfter);
		subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
		subject.getSubjectConfirmations().add(subjectConfirmation);
		return subject;
	}

	/**
	 * Create an authnContext with a given authnContextClassRef.
	 * 
	 * @param authnContextClassRefValue
	 *            The value of the authnContextClassRef
	 * @return The SAML authnContext with the given authnContextClassRef
	 */
	public static AuthnContext createAuthnContext(
			String authnContextClassRefValue) {
		AuthnContext authnContext = buildXMLObject(AuthnContext.class);
		AuthnContextClassRef authnContextClassRef = buildXMLObject(AuthnContextClassRef.class);
		authnContextClassRef.setAuthnContextClassRef(authnContextClassRefValue);
		authnContext.setAuthnContextClassRef(authnContextClassRef);
		return authnContext;
	}

	/**
	 * Create SAML Conditions with an audience element.
	 * 
	 * @param audienceURI
	 *            The value of the audience element
	 * @return The SAML Conditions with the given audience element
	 */
	public static Conditions createAudienceCondition(String audienceURI) {
		Audience audience = buildXMLObject(Audience.class);
		audience.setAudienceURI(audienceURI);
		AudienceRestriction audienceRestriction = buildXMLObject(AudienceRestriction.class);
		audienceRestriction.getAudiences().add(audience);
		Conditions conditions = buildXMLObject(Conditions.class);
		conditions.getAudienceRestrictions().add(audienceRestriction);
		return conditions;
	}

	/**
	 * Create an artifact with a given value.
	 * 
	 * @param value
	 *            The value
	 * @return The SAML Artifact with the given value
	 */
	public static Artifact createArtifact(String value) {
		Artifact artifact = buildXMLObject(Artifact.class);
		artifact.setArtifact(value);
		return artifact;
	}

	/**
	 * Create a SAML status with a given statusCode.
	 * 
	 * @param value
	 *            The value
	 * @return The SAML status with the given statusCode
	 */
	public static Status createStatus(String value) {
		Status status = buildXMLObject(Status.class);
		status.setStatusCode(buildXMLObject(StatusCode.class));
		status.getStatusCode().setValue(value);
		return status;
	}

	/**
	 * Create a SAML signature with a given keyName.
	 * 
	 * @param keyName
	 *            The keyName
	 * @return The SAML signature with the given keyInfo
	 */
	public static Signature createSignature(String keyName) {
		Signature signature = buildXMLObject(Signature.class);
		signature.setKeyInfo(buildXMLObject(KeyInfo.class));
		KeyName kn = buildXMLObject(KeyName.class);
		kn.setValue(keyName);
		signature.getKeyInfo().getKeyNames().add(kn);
		return signature;
	}
	
	/**
	 * Create a SAML email address.
	 */
	public static EmailAddress createEmail(String email) {
		EmailAddress ea = SAMLUtil.buildXMLObject(EmailAddress.class);
		ea.setAddress(email);
		return ea;
	}

	/**
	 * Create a new Organization object.
	 */
	public static Organization createOrganization(String name, String displayName, String url) {
		OrganizationDisplayName display = SAMLUtil.buildXMLObject(OrganizationDisplayName.class);
		display.setName(new LocalizedString(displayName, "en"));
		Organization org = SAMLUtil.buildXMLObject(Organization.class);
		org.getDisplayNames().add(display);

		OrganizationName orgName = SAMLUtil.buildXMLObject(OrganizationName.class);
		orgName.setName(new LocalizedString(name, "en"));
		org.getOrganizationNames().add(orgName);

		OrganizationURL orgUrl = SAMLUtil.buildXMLObject(OrganizationURL.class);
		orgUrl.setURL(new LocalizedString(url, "en"));
		org.getURLs().add(orgUrl);
		return org;
	}
	
	

	/**
	 * Unmarshall a resource file containing a SAML2.0 document in XML to an XMLObject.
	 * 
	 * @return The corresponding {@link XMLObject}
	 */
	public static XMLObject unmarshallElement(InputStream input) {
		try {
			Element samlElement = loadElement(input);

			Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory().getUnmarshaller(samlElement);
			if (unmarshaller == null) {
				log.error("Unable to retrieve unmarshaller by DOM Element");
				throw new IllegalArgumentException("No unmarshaller for " + samlElement);
			}

			return unmarshaller.unmarshall(samlElement);
		} catch (UnmarshallingException e) {
			log.error("Unmarshalling failed when parsing element file " + input, e);
		}

		return null;
	}
	
	public static XMLObject unmarshallElement(Element element) {
		Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory().getUnmarshaller(element);
		if (unmarshaller == null) {
			log.error("Unable to retrieve unmarshaller by DOM Element " + element);
			throw new IllegalArgumentException("No unmarshaller for " + element);
		}
		try {
			return unmarshaller.unmarshall(element);
		} catch (UnmarshallingException e) {
			log.error("Unmarshalling failed when parsing element file " + element, e);
			return null;
		}
	}

	/**
	 * Read the content of a given XML resource file.
	 * 
	 * @param input
	 *            The stream to read from. The stream is not closed.
	 * @return The corresponding {@link Element}
	 */
	public static Element loadElement(InputStream input) {
		try {
            DocumentBuilderFactory newFactory = getDocumentBuilderFactory();
            
            DocumentBuilder builder = newFactory.newDocumentBuilder();

            Document doc = builder.parse(input);
			Element samlElement = doc.getDocumentElement();

			return samlElement;
		} catch (ParserConfigurationException e) {
			log.error("Unable to parse element file " + input, e);
		} catch (SAXException e) {
			log.error("Unable to parse element file " + input, e);
		} catch (IOException e) {
			log.error("Unable to parse element file " + input, e);
		}
		return null;
	}

    private static DocumentBuilderFactory getDocumentBuilderFactory() throws ParserConfigurationException {
        DocumentBuilderFactory newFactory = DocumentBuilderFactory.newInstance();
        newFactory.setNamespaceAware(true);

        newFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        newFactory.setFeature("http://apache.org/xml/features/dom/defer-node-expansion", false);
        newFactory.setFeature("http://javax.xml.XMLConstants/feature/secure-processing", true);
        newFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        newFactory.setExpandEntityReferences(false);
        
        return newFactory;
    }

    /**
	 * Unmarshall a string containing a SAML2.0 document in XML to an XMLObject.
	 * 
	 * @param elementString
	 *            The XML object as a string
	 * @return The corresponding {@link XMLObject}
	 */
	public static XMLObject unmarshallElementFromString(String elementString) {
		try {
			Element samlElement = loadElementFromString(elementString);

			Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory().getUnmarshaller(samlElement);
			if (unmarshaller == null) {
				log.error("Unable to retrieve unmarshaller by DOM Element");
				throw new IllegalArgumentException("No unmarshaller for " + elementString);
			}

			return unmarshaller.unmarshall(samlElement);
		} catch (UnmarshallingException e) {
			log.error("Unmarshalling failed when parsing element string " + elementString, e);
			throw new WrappedException(Layer.DATAACCESS, e);
		}
	}

	/**
	 * Parse an XML string.
	 * 
	 * @param elementString
	 *            The String to parse
	 * @return The corresponding document {@link Element}.
	 */
	public static Element loadElementFromString(String elementString) {
		try {
            DocumentBuilderFactory newFactory = getDocumentBuilderFactory();
            newFactory.setNamespaceAware(true);
            
            DocumentBuilder builder = newFactory.newDocumentBuilder();

			Document doc = builder.parse(new ByteArrayInputStream(elementString.getBytes("UTF-8")));
			Element samlElement = doc.getDocumentElement();

			return samlElement;
		} catch (ParserConfigurationException e) {
			log.error("Unable to parse element string " + elementString, e);
			throw new WrappedException(Layer.DATAACCESS, e);
		} catch (SAXException e) {
			log.error("Ue, nable to parse element string " + elementString, e);
			throw new WrappedException(Layer.DATAACCESS, e);
		} catch (IOException e) {
			log.error("Unable to parse element string " + elementString, e);
			throw new WrappedException(Layer.DATAACCESS, e);
		}
	}

	/**
	 * Unmarshall the content of a file containing a SAML2.0 document in XML to
	 * an XMLObject.
	 * 
	 * @param fileName
	 *            The name of the file from the file system.
	 * @return The corresponding {@link XMLObject}. Returns <code>null</code> if the file does not exist or is malformed.
	 */
	public static XMLObject unmarshallElementFromFile(String fileName) {
		File file = new File(fileName);
		if (!file.isFile() || !file.canRead()) {
			log.error("Can't find or read file " + fileName);
			throw new RuntimeException("Cannot find file " + fileName);
		}

		try {
			Element samlElement = loadElementFromFile(fileName);

			Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory()
					.getUnmarshaller(samlElement);
			if (unmarshaller == null) {
				log.error("Unable to retrieve unmarshaller by DOM Element for {" + samlElement.getNamespaceURI() + "}" + samlElement.getLocalName());
				throw new IllegalArgumentException("No unmarshaller for element {" + samlElement.getNamespaceURI() + "}" + samlElement.getLocalName() + " from file " + fileName);
			}

			return unmarshaller.unmarshall(samlElement);
		} catch (UnmarshallingException e) {
			throw new WrappedException(Layer.DATAACCESS, e);
		}
	}

	/**
	 * Read the content of a given XML file.
	 * 
	 * @param fileName
	 *            The name of the file
	 * 
	 * @return The corresponding {@link Element}
	 */
	public static Element loadElementFromFile(String fileName) {
		try {
			StringBuffer sb = new StringBuffer(2048);
			BufferedReader reader = new BufferedReader(new FileReader(fileName));

			char[] chars = new char[1024];
			int numRead = 0;
			while ((numRead = reader.read(chars)) != -1) {
				String readData = String.valueOf(chars, 0, numRead);
				sb.append(readData);
				chars = new char[1024];
			}
			reader.close();
			if (log.isDebugEnabled()) log.debug(sb.toString());
			return loadElementFromString(sb.toString());
		} catch (IOException e) {
			throw new WrappedException(Layer.DATAACCESS, e);
		}
	}

	/**
	 * Pretty print an XML object.
	 * 
	 * @param object
	 *            The SAML object
	 * @return A SAML object as pretty print XML
	 */
	public static String getSAMLObjectAsPrettyPrintXML(XMLObject object) {
		if (object == null) {
			throw new IllegalArgumentException("Object cannot be null");
		}
		Element e1 = marshallObject(object);

		return XMLHelper.prettyPrintXML(e1);
	}
	
	public static Element marshallObject(XMLObject object) {
		if (object.getDOM() == null) {
			Marshaller m = (Marshaller) Configuration.getMarshallerFactory().getMarshaller(object);
			if (m == null) {
				throw new IllegalArgumentException("No unmarshaller for " + object);
			}
			try {
				return m.marshall(object);
			} catch (MarshallingException e) {
				throw new WrappedException(Layer.CLIENT, e);
			}
		}
		
		return object.getDOM();
	}


	/**
	 * Create a SAML assertion consumer service.
	 */
	public static AssertionConsumerService createAssertionConsumerService(String location, String binding, int index, boolean isDefault) {
		AssertionConsumerService acs = buildXMLObject(AssertionConsumerService.class);
		acs.setBinding(binding);
		acs.setIndex(index);
		acs.setLocation(location);
		acs.setIsDefault(isDefault);
		return acs;
	}

	public static SingleLogoutService createSingleLogoutService(String location, String responseLocation, String binding) {
		SingleLogoutService sls = buildXMLObject(SingleLogoutService.class);
		sls.setBinding(binding);
		sls.setLocation(location);
		sls.setResponseLocation(responseLocation);
		return sls;
	}

	public static ArtifactResolutionService createArtifactResolutionService(String location) {
		ArtifactResolutionService ars = buildXMLObject(ArtifactResolutionService.class);
		ars.setBinding(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
		ars.setIndex(0);
		ars.setIsDefault(true);
		ars.setLocation(location);
		return ars;
	}
	
	public static RequestedAttribute createRequestedAttribute(String attribute, String format, boolean required) {
		RequestedAttribute attr = buildXMLObject(RequestedAttribute.class);
		attr.setIsRequired(required);
		attr.setName(attribute);
		attr.setNameFormat(format);
		
		return attr;
	}
	
	public static NameIDFormat createNameIDFormat(String format) {
	    NameIDFormat nameIdFormat = buildXMLObject(NameIDFormat.class);
	    nameIdFormat.setFormat(format);
	    return nameIdFormat;
	}
	
	public static AttributeConsumingService createAttributeConsumingService(String serviceName) {
		AttributeConsumingService service = SAMLUtil.buildXMLObject(AttributeConsumingService.class);
		ServiceName name = SAMLUtil.buildXMLObject(ServiceName.class);
		name.setName(new LocalizedString(serviceName, "en"));
		service.getNames().add(name);
		
		service.setIndex(0);
		service.setIsDefault(true);

		return service;
	}
	
	/**
	 * Decode the value of a _saml_idp discovery value.
	 * 
	 * @param value A string of entityIds encoded with base64 and separated by space.
	 * @return A list of decoded values. Never <code>null</code>.
	 */
	public static String[] decodeDiscoveryValue(String value) {
		if (value == null) {
			return new String[0];
		}
		String[] ids = value.split(" ");
		for (int i = 0; i < ids.length; i++) {
			ids[i] = new String(Base64.decode(ids[i]));
		}
		return ids;
	}

	public static RequestedAuthnContext createRequestedAuthnContext(List<String> references) {
		RequestedAuthnContext c = buildXMLObject(RequestedAuthnContext.class);
		c.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);

		for (String reference : references) {
			AuthnContextClassRef authnContextClassRef = buildXMLObject(AuthnContextClassRef.class);
			authnContextClassRef.setAuthnContextClassRef(reference);

			c.getAuthnContextClassRefs().add(authnContextClassRef);
		}
		
		return c;
	}

	public static Company createCompany(String orgName) {
		Company c = buildXMLObject(Company.class);
		c.setName(orgName);
		return c;
	}
	
	public static GivenName createGivenName(String givenName) {
		GivenName g = buildXMLObject(GivenName.class);
		g.setName(givenName);
		return g;
	}
	
	public static TelephoneNumber createTelephoneNumber(String phone) {
		TelephoneNumber t = buildXMLObject(TelephoneNumber.class);
		t.setNumber(phone);
		return t;
	}

	public static SurName createSurName(String surName) {
		SurName s = buildXMLObject(SurName.class);
		s.setName(surName);
		return s;
	}

	/**
	 * Get the first element of a specific type from a parent element.
	 * @param obj The parent element. If this is <code>null</code>, <code>null</code> is returned.
	 * @param type The type to retrieve.
	 * @return The first element, or <code>null</code> if no elements were found.
	 */
	@SuppressWarnings("unchecked")
	public static <T extends XMLObject> T  getFirstElement(ElementExtensibleXMLObject obj, Class<T> type) {
		if (obj == null) return null;
		
		for (XMLObject o : obj.getUnknownXMLObjects()) {
			if (type.isInstance(o)) {
				return (T) o;
			}
		}
		return null;
	}
	
	@SuppressWarnings("unchecked")
	/**
	 * Clone a XML object, including all references.
	 */
	public static <T extends XMLObject> T clone(T object) {
		return (T) SAMLUtil.unmarshallElementFromString(XMLHelper.nodeToString(SAMLUtil.marshallObject(object)));
	}
}
