import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.openqa.selenium.By;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

public class IntegrationTest {
    private ChromeDriver driver;
    private WebDriverWait wait;

    @Test
    public void integrationTest() {

        //Navigate to login page
        driver.get("https://localhost:8443/oiosaml3-demo.java/index.jsp");
        wait.until(ExpectedConditions.visibilityOfElementLocated(By.linkText("Page requiring NSIS Substantial"))).click();
        wait.until(ExpectedConditions.visibilityOfElementLocated(By.cssSelector("#Repeater2_LoginMenuItem_3 > div.btn-slice2"))).click();

        //Log in
        wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("ContentPlaceHolder_MitIdSimulatorControl_txtUsername"))).sendKeys("Morten");
        wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("ContentPlaceHolder_MitIdSimulatorControl_txtPassword"))).sendKeys("morten");
        wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("ContentPlaceHolder_MitIdSimulatorControl_btnSubmit"))).click();

        //Verify response
        wait.until(ExpectedConditions.visibilityOfElementLocated(By.xpath("//*[text()='Assertion Content']")));
    }

    @Before
    public void setUpWebDriver() {
        System.setProperty("webdriver.chrome.driver", "bin/chromedriver.exe");

        ChromeOptions chromeOptions = new ChromeOptions();
        chromeOptions.addArguments(
                "--headless"
                );

        driver = new ChromeDriver(chromeOptions);

        wait = new WebDriverWait(driver, 10);
    }

    @After
    public void tearDownWebDriver() {
        driver.quit();
    }

}
