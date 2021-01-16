package dk.itst.oiosaml.idp.dao.model.enums;

public enum LevelOfAssurance {
    LOW("https://data.gov.dk/concept/core/nsis/loa/Low"),
    SUBSTANTIAL("https://data.gov.dk/concept/core/nsis/loa/Substantial"),
    HIGH("https://data.gov.dk/concept/core/nsis/loa/High");

    private String text;

    private LevelOfAssurance(String text) {
        this.text = text;
    }

    public String getText() {
        return text;
    }
}
