package dk.gov.oio.saml.oiobpp;

import java.io.StringReader;

import javax.xml.bind.JAXBContext;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class OIOBPPUtilTest {

    @DisplayName("Test valid OIOBPP string")
    @Test
    public void testValidString() {
        PrivilegeList result = OIOBPPUtil.parse(validString);

        Assertions.assertNotNull(result);
        Assertions.assertEquals(2, result.privilegeGroup.size());
        Assertions.assertEquals(2, result.privilegeGroup.get(0).constraint.size());
        Assertions.assertEquals(1, result.privilegeGroup.get(0).privilege.size());
        Assertions.assertEquals("urn:dk:some_domain:myPrivilege1A", result.privilegeGroup.get(0).privilege.get(0));
        Assertions.assertEquals(null, result.privilegeGroup.get(1).constraint);
        Assertions.assertEquals(2, result.privilegeGroup.get(1).privilege.size());
        Assertions.assertEquals("urn:dk:some_domain:myPrivilege1C", result.privilegeGroup.get(1).privilege.get(0));
    }
    
    @DisplayName("Test that the PrivilegeList is read whether JAXB wraps it in a JAXBElement or not")
    @Test
    public void testWrappedAndUnwrappedResult() throws Exception {
        // Through the ObjectFactory the element declaration applies and the result is a JAXBElement; with only the
        // PrivilegeList class the root element annotation applies and the result is the PrivilegeList itself, as with
        // some other JAXB implementations
        Object raw = JAXBContext.newInstance(PrivilegeList.class).createUnmarshaller().unmarshal(new StringReader(validString));
        Assertions.assertTrue(raw instanceof PrivilegeList, "This context must give an unwrapped PrivilegeList for the test to cover issue #68");

        PrivilegeList wrapped = OIOBPPUtil.unmarshal(JAXBContext.newInstance(ObjectFactory.class), validString);
        PrivilegeList unwrapped = OIOBPPUtil.unmarshal(JAXBContext.newInstance(PrivilegeList.class), validString);

        Assertions.assertEquals(2, wrapped.privilegeGroup.size());
        Assertions.assertEquals(2, unwrapped.privilegeGroup.size());
        Assertions.assertEquals("urn:dk:some_domain:myPrivilege1A", unwrapped.privilegeGroup.get(0).privilege.get(0));
    }

    @DisplayName("Test invalid OIOBPP string")
    @Test
    public void testInvalidString() {
        PrivilegeList result = OIOBPPUtil.parse(invalidString);

        Assertions.assertEquals(null, result);
    }
    
    @DisplayName("Test OIOBPP string with a document type declaration")
    @Test
    public void testStringWithDoctype() {
        PrivilegeList result = OIOBPPUtil.parse(doctypeString);

        Assertions.assertEquals(null, result);
    }

    private static final String validString = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" + 
            "<bpp:PrivilegeList xmlns:bpp=\"http://digst.dk/oiosaml/basic_privilege_profile\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\n" + 
            " <PrivilegeGroup Scope=\"urn:dk:gov:saml:cvrNumberIdentifier:12345678\">\n" + 
            "   <Privilege>urn:dk:some_domain:myPrivilege1A</Privilege>\n" + 
            "   <Constraint Name=\"urn:dk:kombit:KLE\">25.*</Constraint>\n" + 
            "   <Constraint Name=\"urn:dk:kombit:sensitivity\">3</Constraint> " +
            " </PrivilegeGroup>\n" + 
            " <PrivilegeGroup Scope=\"urn:dk:gov:saml:seNumberIdentifier:27384223\">\n" + 
            "   <Privilege>urn:dk:some_domain:myPrivilege1C</Privilege>\n" + 
            "   <Privilege>urn:dk:some_domain:myPrivilege1D</Privilege>\n" + 
            " </PrivilegeGroup>\n" + 
            "</bpp:PrivilegeList>";
    
    // Entities declared in the document type declaration expand into each other, so a short document turns
    // into a very large one while it is parsed
    private static final String doctypeString = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<!DOCTYPE bpp:PrivilegeList [\n" +
            " <!ENTITY a \"aaaaaaaaaa\">\n" +
            " <!ENTITY b \"&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;\">\n" +
            " <!ENTITY c \"&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;\">\n" +
            "]>\n" +
            "<bpp:PrivilegeList xmlns:bpp=\"http://digst.dk/oiosaml/basic_privilege_profile\">\n" +
            " <PrivilegeGroup Scope=\"urn:dk:gov:saml:cvrNumberIdentifier:12345678\">\n" +
            "   <Privilege>&c;</Privilege>\n" +
            " </PrivilegeGroup>\n" +
            "</bpp:PrivilegeList>";

    private static final String invalidString = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" + 
            "<bpp:PrivilegeList xmlns:bpp=\"http://digst.dk/oiosaml/basic_privilege_profile\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\n" + 
            " <PrivilegeGroup Scope=\"urn:dk:gov:saml:cvrNumberIdentifier:12345678\">\n" + 
            "   <Privilege>urn:dk:some_domain:myPrivilege1A</Privilege>\n" + 
            "   <Constraint Name=\"urn:dk:kombit:KLE\">25.*</Constraint>\n" + 
            "   <Constraint Name=\"urn:dk:kombit:sensitivity\">3</Constraint> " +
            " </PrivilegeGroup\n" + // error is missing > 
            " <PrivilegeGroup Scope=\"urn:dk:gov:saml:seNumberIdentifier:27384223\">\n" + 
            "   <Privilege>urn:dk:some_domain:myPrivilege1C</Privilege>\n" + 
            "   <Privilege>urn:dk:some_domain:myPrivilege1D</Privilege>\n" + 
            " </PrivilegeGroup>\n" + 
            "</bpp:PrivilegeList>";

}
