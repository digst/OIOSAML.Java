package dk.itst.oiosaml.idp.config;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ServiceProvider {

    private String entityID;

    private String metadataURL;
}
