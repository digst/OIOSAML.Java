import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
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
        wait.until(ExpectedConditions.visibilityOfElementLocated(By.cssSelector("[href*='/login.aspx/mitidsim']"))).click();

        //Log in
        wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("ContentPlaceHolder_MitIdSimulatorControl_txtUsername"))).sendKeys("Tilo");
        wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("ContentPlaceHolder_MitIdSimulatorControl_txtPassword"))).sendKeys("Test1234");
        wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("ContentPlaceHolder_MitIdSimulatorControl_btnSubmit"))).click();

        //Verify response
        wait.until(ExpectedConditions.visibilityOfElementLocated(By.xpath("//*[text()='Assertion Content']")));
    }

    @Before
    public void setUpWebDriver() {
        System.setProperty("webdriver.chrome.driver", "C:\\tools\\chromedriver.exe");

        ChromeOptions chromeOptions = new ChromeOptions();
        chromeOptions.addArguments(
                "--headless",
                "--allow-insecure-localhost"
                );

        driver = new ChromeDriver(chromeOptions);

        wait = new WebDriverWait(driver, 10);
    }

    @After
    public void tearDownWebDriver() {
        driver.quit();
    }

}
