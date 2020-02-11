package dk.itst.oiosaml.idp.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@Getter
@Setter
@ConfigurationProperties(prefix = "service.provider")
public class ServiceProviderConfig {
    private List<ServiceProvider> providers;
}
