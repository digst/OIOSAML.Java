package dk.itst.oiosaml.sp.bindings;

import org.jmock.Expectations;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.common.xml.SAMLConstants;

import dk.itst.oiosaml.sp.model.OIOAuthnRequest;
import dk.itst.oiosaml.sp.service.AbstractServiceTests;

public class ArtifactBindingHandlerTest extends AbstractServiceTests {

	private ArtifactBindingHandler artifactBindingHandler;
	private OIOAuthnRequest request;

	@Before
	public void setUp() throws Exception {
		artifactBindingHandler = new ArtifactBindingHandler();
		
		request = OIOAuthnRequest.buildAuthnRequest("http://ssoServiceLocation", "spEntityId", SAMLConstants.SAML2_ARTIFACT_BINDING_URI, handler, "state", "http://localhost");
	}

	@Test
	public void handle() throws Exception {
		context.checking(new Expectations() {{ 
			one(res).sendRedirect(with(any(String.class)));
		}});
		artifactBindingHandler.handle(req, res, credential, request);
	}
	
}
