package dk.itst.oiosaml.sp.metadata;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Collection;

import org.junit.Before;
import org.junit.Test;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.xml.security.credential.Credential;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.sp.AbstractTests;
import dk.itst.oiosaml.sp.metadata.IdpMetadata;
import dk.itst.oiosaml.sp.metadata.IdpMetadata.Metadata;
import dk.itst.oiosaml.sp.service.TestHelper;

public class IdpMetadataTest extends AbstractTests {
	
	private EntityDescriptor ed1;
	private EntityDescriptor ed2;
	private IdpMetadata md;

	@Before
	public void setup() throws Exception {
		Credential credential = TestHelper.getCredential();
		ed1 = TestHelper.buildEntityDescriptor(credential);
		ed1.setEntityID("ed1");
		ed2 = TestHelper.buildEntityDescriptor(credential);
		ed2.setEntityID("ed2");
		md = new IdpMetadata(SAMLConstants.SAML20P_NS, ed1, ed2);
	}
	
	@Test(expected=IllegalStateException.class)
	public void dontCreateWhenMissingCertificate() throws Exception {
		EntityDescriptor ed = SAMLUtil.buildXMLObject(EntityDescriptor.class);
		new IdpMetadata(SAMLConstants.SAML20P_NS, ed);
	}

	@Test
	public void testGetExistingMetadata() {
		Metadata metadata = md.getMetadata("ed1");
		assertEquals("ed1", metadata.getEntityID());
	}
	
	@Test(expected=IllegalArgumentException.class)
	public void getFailOnNoEntityId() {
		md.getMetadata("test");
	}

	@Test
	public void testEnableDiscovery() {
		assertTrue(md.enableDiscovery());
		
		assertFalse(new IdpMetadata(SAMLConstants.SAML20P_NS, ed1).enableDiscovery());
	}

	@Test
	public void testGetEntityIDs() {
		Collection<String> ids = md.getEntityIDs();
		assertEquals(2, ids.size());
		assertTrue(ids.contains("ed1"));
		assertTrue(ids.contains("ed2"));
	}

	@Test
	public void testFindSupportedEntity() {
		Metadata metadata = md.findSupportedEntity("test", "ed2");
		assertNotNull(metadata);
		assertEquals("ed2", metadata.getEntityID());
	}
	
	@Test
	public void findSupportedEntityShouldReturnNullOnNoMatch() {
		assertNull(md.findSupportedEntity("test1", "test2", "test3"));
	}

	@Test
	public void testGetSignonLocationByBinding() throws Exception {
		Metadata metadata = md.getMetadata("ed1");
		assertNotNull(metadata.getSingleSignonServiceLocation(SAMLConstants.SAML2_ARTIFACT_BINDING_URI));
	}
	
	@Test(expected=IllegalArgumentException.class)
	public void getSignonLocationShouldFailOnInvalidBinding() {
		md.getMetadata("ed1").getSingleSignonServiceLocation("binding");
	}
	
	@Test
	public void testAttributeServiceLocation() {
		md.getMetadata("ed1").getAttributeQueryServiceLocation(SAMLConstants.SAML2_SOAP11_BINDING_URI);
	}
	
	@Test(expected=IllegalArgumentException.class)
	public void testAttributeServiceLocationShouldFailOnInvalidBinding() {
		md.getMetadata("ed1").getAttributeQueryServiceLocation("test");
	}
	
	@Test(expected=IllegalArgumentException.class)
	public void testAttributeServiceLocationShouldFailOnNoDescriptor() {
		ed1.getRoleDescriptors().clear();
		md.getMetadata("ed1").getAttributeQueryServiceLocation(SAMLConstants.SAML2_SOAP11_BINDING_URI);
	}
	
	@Test
	public void same_entity_id_must_be_merged_to_one_with_multiple_certificates() throws Exception {
		EntityDescriptor ed3 = TestHelper.buildEntityDescriptor(TestHelper.getCredential());
		ed3.setEntityID("ed1");
		IdpMetadata md = new IdpMetadata(SAMLConstants.SAML20P_NS, ed1, ed2, ed3);

		assertEquals(2, md.getEntityIDs().size());
		assertEquals(2, md.getMetadata("ed1").getCertificates().size());
	}

}