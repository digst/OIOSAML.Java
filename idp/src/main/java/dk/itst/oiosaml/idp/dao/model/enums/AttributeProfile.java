package dk.itst.oiosaml.idp.dao.model.enums;

public enum AttributeProfile {
    PERSON("https://data.gov.dk/eid/Person"),
    PROFESSIONAL("https://data.gov.dk/eid/Professional");

    private String URI;

    private AttributeProfile(String URI) {
        this.URI = URI;
    }

    public String getURI() {
        return URI;
    }
}
