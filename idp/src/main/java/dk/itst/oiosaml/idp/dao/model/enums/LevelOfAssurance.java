package dk.itst.oiosaml.idp.dao.model.enums;

public enum LevelOfAssurance {
    LOW("Low"),
    SUBSTANTIAL("Substantial"),
    HIGH("High");

    private String text;

    private LevelOfAssurance(String text) {
        this.text = text;
    }

    public String getText() {
        return text;
    }
}
