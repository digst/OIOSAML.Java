package dk.itst.oiosaml.idp.service;

import net.shibboleth.utilities.java.support.resource.Resource;
import org.springframework.core.io.UrlResource;

import java.io.IOException;
import java.net.URL;

public class HttpMetadataResource extends UrlResource implements Resource {

    public HttpMetadataResource(URL url) {
        super(url);
    }

    @Override
    public boolean exists() {
        return true;
    }

    @Override
    public Resource createRelativeResource(String relativePath) throws IOException {
        return null;
    }
}
