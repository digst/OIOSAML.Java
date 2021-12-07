package dk.gov.oio.saml.oiobpp;

import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;
import java.util.Base64;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.transform.Source;
import javax.xml.transform.sax.SAXSource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.InputSource;
import org.xml.sax.SAXNotRecognizedException;
import org.xml.sax.SAXNotSupportedException;

public class OIOBPPUtil {
    private static final Logger log = LoggerFactory.getLogger(OIOBPPUtil.class);

	@SuppressWarnings("unchecked")
	public static PrivilegeList parse(String object) {
		// we accept both base64 encoded input, and "raw" xml-strings
		try {
			object = new String(Base64.getDecoder().decode(object.getBytes(Charset.forName("UTF-8"))));
		}
		catch (Exception ex) {
			; // ignore
		}

		try {
			JAXBContext context = JAXBContext.newInstance(ObjectFactory.class);
			Unmarshaller unmarsheller = context.createUnmarshaller();
			JAXBElement<PrivilegeList> privilegeList = (JAXBElement<PrivilegeList>) unmarsheller.unmarshal(getSecureSource(object));
	
			return privilegeList.getValue();
		}
		catch (Exception ex) {
			log.error("Failed to parse input string: {}", object, ex);
		}

		return null;
	}
	
	private static Source getSecureSource(String object) throws JAXBException {
		try {
			SAXParserFactory spf = getSecureSAXParserFactory();
			return new SAXSource(spf.newSAXParser().getXMLReader(), new InputSource(new ByteArrayInputStream(object.getBytes(Charset.forName("UTF-8")))));
		}
		catch (Exception ex) {
			throw new JAXBException("Failed to securely unmarshall object", ex);
		}
	}
		
	private static SAXParserFactory getSecureSAXParserFactory() throws SAXNotRecognizedException, SAXNotSupportedException, ParserConfigurationException {
		SAXParserFactory spf = SAXParserFactory.newInstance();
		spf.setNamespaceAware(true);
		spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
		spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
		spf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

		return spf;
	}
}
