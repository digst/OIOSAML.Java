package dk.gov.oio.saml.util;

import java.io.StringWriter;
import java.util.stream.Collectors;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.joda.time.DateTime;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.StatusMessage;
import org.opensaml.saml.saml2.core.impl.AssertionMarshaller;
import org.w3c.dom.Element;


// TODO: Refactor this class
public class LoggingUtil {
	private static final Logger log = LoggerFactory.getLogger(LoggingUtil.class);

	public static void logAuthnRequest(AuthnRequest authnRequest) {
		if (authnRequest == null) {
			log.warn("Could not log AuthnRequest, was null");
			return;
		}

		if (log.isDebugEnabled()) {
			// If we are debugging, log the entire AuthnRequest
			try {
				Element element = SamlHelper.marshallObject(authnRequest);

				log.debug("authnRequest: " + elementToString(element));
			}
			catch (MarshallingException e) {
				log.error("Could not marshall AuthnRequest for logging purposes");
			}
		}
		else if (log.isInfoEnabled()) {
			// If not, log info as a one liner
			String id = authnRequest.getID();

			Issuer issuer = authnRequest.getIssuer();
			String issuerStr = "";
			if (issuer != null) {
				issuerStr = issuer.getValue();
			}

			DateTime issueInstant = authnRequest.getIssueInstant();
			String instant = "";
			if (issueInstant != null) {
				instant = issueInstant.toString();
			}

			String destination = authnRequest.getDestination();

			log.info("Outgoing AuthnRequest - ID:'" + id + "' Issuer:'" + issuerStr + "' IssueInstant:'" + instant + "' Destination:'" + destination + "'");
		}
	}

	public static void logResponse(Response response, String prefix) {
		if (log.isInfoEnabled()) {
			if (response == null) {
				log.warn("Could not log Response, was null");
				return;
			}
			
			String id = response.getID();
			String destination = response.getDestination();
			String inResponseTo = response.getInResponseTo();

			DateTime issueInstant = response.getIssueInstant();
			String instant = "";
			if (issueInstant != null) {
				instant = issueInstant.toString();
			}

			Issuer issuer = response.getIssuer();
			String issuerStr = "";
			if (issuer != null) {
				issuerStr = issuer.getValue();
			}

			Status status = response.getStatus();
			String statusStr = "";
			if (status != null) {
				StatusCode code = status.getStatusCode();
				if (code != null) {
					statusStr += code.getValue();
				}

				StatusMessage message = status.getStatusMessage();
				if (message != null) {
					statusStr += " " + message.getMessage();
				}
			}

			log.info(prefix + " Response - ID:'" + id + "' InResponseTo:'" + inResponseTo + "' Issuer:'" + issuerStr + "' Status:'" + statusStr + "' IssueInstant:'" + instant + "' Destination:'" + destination + "'");
		}
	}

	public static void logAssertion(Assertion assertion) {
		if (log.isInfoEnabled()){
			if (assertion == null) {
				log.warn("Could not log AuthnRequest, was null");
				return;
			}

			try {
				AssertionMarshaller marshaller = new AssertionMarshaller();
				Element element = marshaller.marshall(assertion);
				
				log.info("Assertion: " + elementToString(element));
			}
			catch (MarshallingException e) {
				log.error("Could not marshall Assertion for logging purposes");
			}
		}
	}

	public static void logLogoutRequest(LogoutRequest logoutRequest, String prefix) {
		if (logoutRequest == null) {
			log.warn("Could not log LogoutRequest, was null");
			return;
		}

		if (log.isDebugEnabled()) {
			try {
				Element element = SamlHelper.marshallObject(logoutRequest);
				log.debug("LogoutRequest: " + elementToString(element));
			} catch (MarshallingException e) {
				log.error("Could not marshall LogoutRequest for logging purposes");
			}
		}
		else if (log.isInfoEnabled()) {
			String id = logoutRequest.getID();

			DateTime issueInstant = logoutRequest.getIssueInstant();
			String instant = "";
			if (issueInstant != null) {
				instant = issueInstant.toString();
			}

			Issuer issuer = logoutRequest.getIssuer();
			String issuerStr = "";
			if (issuer != null) {
				issuerStr = issuer.getValue();
			}

			String sessionIndexes = logoutRequest.getSessionIndexes().stream().map(sessionIndex -> sessionIndex.getSessionIndex()).collect(Collectors.joining(", ", "[", "]"));
			String destination = logoutRequest.getDestination();

			log.info(prefix + " LogoutRequest - ID:'" + id + "' Issuer:'" + issuerStr + "' IssueInstant:'" + instant + "' SessionIndexes:" + sessionIndexes + "' Destination:'" + destination + "'");
		}
	}

	public static void logLogoutResponse(LogoutResponse logoutResponse, String prefix) {
		if (logoutResponse == null) {
			log.warn("Could not log LogoutResponse, was null");
			return;
		}

		if (log.isDebugEnabled()) {
			try {
				Element element = SamlHelper.marshallObject(logoutResponse);
				log.debug("LogoutResponse: " + elementToString(element));
			} catch (MarshallingException e) {
				log.error("Could not marshall LogoutResponse for logging purposes");
			}
		}
		else if (log.isInfoEnabled()) {
			String id = logoutResponse.getID();

			DateTime issueInstant = logoutResponse.getIssueInstant();
			String instant = "";
			if (issueInstant != null) {
				instant = issueInstant.toString();
			}

			Issuer issuer = logoutResponse.getIssuer();
			String issuerStr = "";
			if (issuer != null) {
				issuerStr = issuer.getValue();
			}

			String inResponseTo = logoutResponse.getInResponseTo();

			Status status = logoutResponse.getStatus();
			String statusStr = "";
			if (status != null) {
				StatusCode code = status.getStatusCode();
				if (code != null) {
					statusStr += code.getValue();
				}

				StatusMessage message = status.getStatusMessage();
				if (message != null) {
					statusStr += " " + message.getMessage();
				}
			}

			String destination = logoutResponse.getDestination();

			log.info(prefix + " LogoutResponse - ID:'" + id + "' InResponseTo:'" + inResponseTo + "' Issuer:'" + issuerStr + "' Status:'" + statusStr + "' IssueInstant:'" + instant + "' Destination:'" + destination + "'");
		}
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
    		log.warn("Failed to convert Element to string", ex);
    		
    		return null;
    	}
    }
}
