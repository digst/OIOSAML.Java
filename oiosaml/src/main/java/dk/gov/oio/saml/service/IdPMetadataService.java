package dk.gov.oio.saml.service;

import java.util.HashMap;
import java.util.Map;

import org.opensaml.saml.saml2.metadata.SingleLogoutService;

import dk.gov.oio.saml.config.Configuration;
import dk.gov.oio.saml.model.IdPMetadata;
import dk.gov.oio.saml.util.ExternalException;
import dk.gov.oio.saml.util.InternalException;

public class IdPMetadataService {

    // Single instance
    private static IdPMetadataService singleInstance = new IdPMetadataService();

    public static IdPMetadataService getInstance() {
        return singleInstance;
    }

    // Metadata Service
    private Map<String, IdPMetadata> identityProviders = new HashMap<>();

    public void clear(String entityId) {
        identityProviders.remove(entityId);
    }

    public void clearAll() {
        identityProviders.clear();
    }

    public IdPMetadata getIdPMetadata() throws ExternalException, InternalException {
        // This method is needed since we only have one IdP functionality for now.
        Configuration config = OIOSAML3Service.getConfig();
        
        return getIdPMetadata(config.getIdpEntityID(), config.getIdpMetadataUrl(), config.getIdpMetadataFile());
    }

    public SingleLogoutService getLogoutEndpoint() throws InternalException, ExternalException {
        return getIdPMetadata().getLogoutEndpoint();
    }

    public String getLogoutResponseEndpoint() throws InternalException, ExternalException {
        return getIdPMetadata().getLogoutResponseEndpoint();
    }

    private IdPMetadata getIdPMetadata(String idpEntityID, String idpMetadataURL, String idpMetadataFilePath) throws InternalException, ExternalException {
        IdPMetadata idPMetadata = identityProviders.get(idpEntityID);

        // If IdP Metadata has not been fetched before, create object
        if (idPMetadata == null) {
            idPMetadata = new IdPMetadata(idpEntityID, idpMetadataURL, idpMetadataFilePath);
            identityProviders.put(idpEntityID, idPMetadata);
        }

        return idPMetadata;
    }
}