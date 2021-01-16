package dk.gov.oio.saml.model;

import dk.gov.oio.saml.util.Constants;

public enum NSISLevel {
    NONE(0),
    LOW(1),
    SUBSTANTIAL(2),
    HIGH(3);

    private int level;

    private NSISLevel(int level) {
        this.level = level;
    }

    public boolean equalOrLesser(NSISLevel other) {
        if (other == null) {
            return false;
        }

        return this.level <= other.level;
    }

    public boolean isGreater(NSISLevel other) {
        if (other == null) {
            return true;
        }
        return this.level > other.level;
    }

    public static NSISLevel getNSISLevelFromLOA(String loa, NSISLevel Default) {
        NSISLevel nsisLevel = Default;

        if (loa == null) {
            return nsisLevel;
        }

        switch (loa) {
            case Constants.LOA_LOW:
                nsisLevel = NSISLevel.LOW;
                break;
            case Constants.LOA_SUBSTANTIAL:
                nsisLevel = NSISLevel.SUBSTANTIAL;
                break;
            case Constants.LOA_HIGH:
                nsisLevel = NSISLevel.HIGH;
                break;
        }
        return nsisLevel;
    }
}