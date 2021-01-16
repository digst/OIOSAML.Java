package dk.gov.oio.saml.servlet;

import dk.gov.oio.saml.util.InternalException;
import dk.gov.oio.saml.util.TestConstants;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringReader;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.ParserConfigurationException;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.impl.EntityDescriptorUnmarshaller;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

public class MetadataHandlerTest {

	@DisplayName("Test that SP returns valid metadata from handler endpoint")
	@Test
	public void testMetadata() throws IOException, UnmarshallingException, SAXException, ParserConfigurationException, XMLParserException, InternalException, InitializationException {
		HttpServletRequest request = Mockito.mock(HttpServletRequest.class);

		PrintWriter writer = Mockito.mock(PrintWriter.class);

		HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
		Mockito.when(response.getWriter()).thenReturn(writer);

		MetadataHandler metadataHandler = new MetadataHandler();
		metadataHandler.handleGet(request, response);

		Mockito.verify(response).setContentType("application/xml");

		ArgumentCaptor<String> argument = ArgumentCaptor.forClass(String.class);
		Mockito.verify(writer).print(argument.capture());

		// Take "sent" metadata and parse is to a EntityDescriptor object
		Object metadataRaw = argument.getValue();
		Assertions.assertNotNull(metadataRaw);
		Assertions.assertTrue(metadataRaw instanceof String);
		String metadataStr = (String) metadataRaw;
		Document doc = XMLObjectProviderRegistrySupport.getParserPool().parse(new StringReader(metadataStr));

		EntityDescriptorUnmarshaller metadataUnmarshaller = new EntityDescriptorUnmarshaller();
		XMLObject unmarshall = metadataUnmarshaller.unmarshall(doc.getDocumentElement());

		Assertions.assertNotNull(unmarshall);
		Assertions.assertTrue(unmarshall instanceof EntityDescriptor);

		EntityDescriptor metadata = (EntityDescriptor) unmarshall;
		Assertions.assertEquals(TestConstants.SP_ENTITY_ID, metadata.getEntityID());
	}
}
