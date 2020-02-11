package dk.itst.oiosaml.sp.sso;

import junit.framework.Assert;
import org.junit.Test;
import org.openqa.selenium.Keys;

public class LoginTest extends EnvironmentSetup {

    @Test
    public void testLoaTooLow() {
        driver.get(BASE);
        driver.findElementByLinkText("Page requiring login").click();

        driver.findElementById("username").sendKeys("session1");
        driver.findElementById("password").sendKeys("1");
        driver.findElementById("submitButton").sendKeys(Keys.ENTER);

        String pageSource = driver.getPageSource();
        Assert.assertTrue(pageSource.contains("NSIS level too low"));
    }

    @Test
    public void testCorrectLogin() {
        driver.get(BASE);
        driver.findElementByLinkText("Page requiring login").click();

        driver.findElementById("username").sendKeys("session2");
        driver.findElementById("password").sendKeys("2");
        driver.findElementById("submitButton").sendKeys(Keys.ENTER);

        String pageSource = driver.getPageSource();
        Assert.assertTrue(pageSource.contains("session2"));
        Assert.assertTrue(pageSource.contains("Substantial"));
        Assert.assertTrue(pageSource.contains("Log out"));
    }

    @Test
    public void testLoaTooHigh() {
        driver.get(BASE);
        driver.findElementByLinkText("Page requiring login").click();

        driver.findElementById("username").sendKeys("session3");
        driver.findElementById("password").sendKeys("3");
        driver.findElementById("submitButton").sendKeys(Keys.ENTER);

        String pageSource = driver.getPageSource();
        Assert.assertTrue(pageSource.contains("session3"));
        Assert.assertTrue(pageSource.contains("High"));
        Assert.assertTrue(pageSource.contains("Log out"));
    }

    @Test
    public void testMissingAttributes() {
        driver.get(BASE);
        driver.findElementByLinkText("Page requiring login").click();

        driver.findElementById("username").sendKeys("session4");
        driver.findElementById("password").sendKeys("4");
        driver.findElementById("submitButton").sendKeys(Keys.ENTER);

        String pageSource = driver.getPageSource();
        Assert.assertTrue(pageSource.contains("Problem accessing /sp/priv1.jsp"));
    }

    @Test
    public void testMissingNameId() {
        driver.get(BASE);
        driver.findElementByLinkText("Page requiring login").click();

        driver.findElementById("username").sendKeys("session5");
        driver.findElementById("password").sendKeys("5");
        driver.findElementById("submitButton").sendKeys(Keys.ENTER);

        String pageSource = driver.getPageSource();
        Assert.assertTrue(pageSource.contains("Unable to validate SAML message!"));
    }

    @Test
    public void testProfessionalProfile() {
        driver.get(BASE);
        driver.findElementByLinkText("Page requiring login").click();

        driver.findElementById("username").sendKeys("session6");
        driver.findElementById("password").sendKeys("6");
        driver.findElementById("submitButton").sendKeys(Keys.ENTER);

        String pageSource = driver.getPageSource();
        Assert.assertTrue(pageSource.contains("session6"));
        Assert.assertTrue(pageSource.contains("Log out"));
        Assert.assertTrue(pageSource.contains("https://data.gov.dk/model/core/eid/professional/orgName"));
        Assert.assertTrue(pageSource.contains("https://data.gov.dk/model/core/eid/professional/cvr"));
    }
}
