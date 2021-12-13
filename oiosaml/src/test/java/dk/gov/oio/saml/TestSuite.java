package dk.gov.oio.saml;

import org.junit.platform.runner.JUnitPlatform;
import org.junit.platform.suite.api.SelectPackages;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
@SelectPackages( {
    "dk.gov.oio.saml.filter",
    "dk.gov.oio.saml.oiobpp",
    "dk.gov.oio.saml.service",
    "dk.gov.oio.saml.service.validation",
    "dk.gov.oio.saml.servlet"
})
public class TestSuite {

}
