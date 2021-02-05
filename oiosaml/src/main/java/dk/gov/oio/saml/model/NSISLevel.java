package dk.gov.oio.saml.model;

import java.util.Arrays;
import java.util.function.Predicate;

public enum NSISLevel {
    NONE(0, 0, null),
    LOW(1, 2, "Low"),
    SUBSTANTIAL(2, 3, "Substantial"),
    HIGH(3, 3, "High");

    private static final String URL_PREFIX = "https://data.gov.dk/concept/core/nsis/loa/";

    private int level;
    private int assuranceLevel;
    private String name;

    NSISLevel(int level, int assuranceLevel, String name) {
        this.level = level;
        this.assuranceLevel = assuranceLevel;
        this.name = name;
    }

    public int getAssuranceLevel() {
        return assuranceLevel;
    }

    public String getName() {
        return name;
    }

    public String getUrl() {
        return URL_PREFIX + name;
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

    public static NSISLevel getNSISLevelFromAttributeValue(String value, NSISLevel Default) {
        if (value == null) {
            return Default;
        }

        return getNSISLevelFromPredicate(level -> value.equals(level.getName()), Default);
    }

    public static NSISLevel getNSISLevelFromUrl(String url, NSISLevel Default) {
        if(url == null) {
            return Default;
        }

        return getNSISLevelFromPredicate(level -> url.equals(level.getUrl()), Default);
    }

    private static NSISLevel getNSISLevelFromPredicate(Predicate<NSISLevel> predicate, NSISLevel Default) {
        return Arrays.stream(values()).filter(predicate).findFirst().orElse(Default);
    }
}