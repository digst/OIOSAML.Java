package dk.itst.oiosaml.idp;

import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.xmlsec.config.impl.JavaCryptoValidationInitializer;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication(scanBasePackages = "dk.itst.oiosaml.idp")
@ComponentScan(basePackages = "dk.itst.oiosaml.idp")
public class Application {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);

        try {
            JavaCryptoValidationInitializer cryptoValidationInitializer = new JavaCryptoValidationInitializer();
            cryptoValidationInitializer.init();
            InitializationService.initialize();

        } catch (InitializationException e) {
            e.printStackTrace();
        }
    }
}
