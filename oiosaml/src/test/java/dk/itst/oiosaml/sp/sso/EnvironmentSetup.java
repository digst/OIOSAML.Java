package dk.itst.oiosaml.sp.sso;

import dk.itst.oiosaml.configuration.SAMLConfigurationFactory;
import dk.itst.oiosaml.sp.metadata.IdpMetadata;
import dk.itst.oiosaml.sp.metadata.SPMetadata;
import dk.itst.oiosaml.sp.service.util.Constants;
import org.apache.commons.io.FileUtils;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.mortbay.jetty.Server;
import org.mortbay.jetty.webapp.WebAppContext;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.opensaml.DefaultBootstrap;
import org.opensaml.xml.security.x509.BasicX509Credential;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public abstract class EnvironmentSetup {
    protected static final String BASE = "http://sp:8443/";
    protected ChromeDriver driver;
    private static Server server;
    private static File tmpdir;

    @BeforeClass
    public static void configure() throws Exception {
        DefaultBootstrap.bootstrap();
    }

    @BeforeClass
    public static void setupServer() throws Exception {
        // Create temp folder for config
        tmpdir = new File(System.getProperty("java.io.tmpdir") + "/oiosaml-" + Math.random());
        tmpdir.mkdir();

        // Reinitialize SAMLConfiguration
        Map<String, String> params = new HashMap<>();
        params.put(Constants.INIT_OIOSAML_HOME, tmpdir.getAbsolutePath());

        String source = "./src/test/resources/test-oiosaml-folder";
        File srcDir = new File(source);

        try {
            FileUtils.copyDirectory(srcDir, tmpdir);
        } catch (IOException e) {
            e.printStackTrace();
        }

        SAMLConfigurationFactory.getConfiguration().setInitConfiguration(params);

        server = new Server(8443);
        WebAppContext wac = new WebAppContext();
        wac.setClassLoader(Thread.currentThread().getContextClassLoader());
        wac.setWar("src/test/resources/webapp/");

        server.setHandler(wac);
        server.start();
    }

    @Before
    public void setUpWebDriver() {
        System.setProperty("webdriver.chrome.driver", "bin/chromedriver");

        ChromeOptions chromeOptions = new ChromeOptions();
        chromeOptions.addArguments(
                "--headless",
                "--allow-insecure-localhost",
                "--ignore-certificate-errors",
                "--enable-javascript",
                "acceptInsecureCerts");

        driver = new ChromeDriver(chromeOptions);
    }

    @After
    public void tearDownWebDriver() {
        driver.quit();
    }

    @AfterClass
    public static void tearDownServer() throws Exception {
        if (server != null) {
            server.stop();
        }
        if (tmpdir != null) {
            FileUtils.deleteDirectory(tmpdir);
        }
    }
}
