package dk.gov.oio.saml.model;

import dk.gov.oio.saml.util.Constants;

public enum NSISLevel {
    NONE(0, 0),
    LOW(1, 2),
    SUBSTANTIAL(2, 3),
    HIGH(3, 3);

    private int level;
    private int assuranceLevel;

    private NSISLevel(int level, int assuranceLevel) {
        this.level = level;
        this.assuranceLevel = assuranceLevel;
    }

    public int getAssuranceLevel() {
        return assuranceLevel;
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
            case Constants.LOA_LOW_VALUE:
                nsisLevel = NSISLevel.LOW;
                break;
            case Constants.LOA_SUBSTANTIAL_VALUE:
                nsisLevel = NSISLevel.SUBSTANTIAL;
                break;
            case Constants.LOA_HIGH_VALUE:
                nsisLevel = NSISLevel.HIGH;
                break;
        }
        return nsisLevel;
    }
}