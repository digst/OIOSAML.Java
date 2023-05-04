package dk.gov.oio.saml.extensions.appswitch;

import java.util.Arrays;

public enum AppSwitchPlatform {
    Android("Android"),
    iOS("iOS");

    private final String name;

    AppSwitchPlatform(String name) {

        this.name = name;
    }

    public String getName() {
        return name;
    }

    public static AppSwitchPlatform getPlatformOrNull(String value) {
        if (value == null) {
            return null;
        }

        return Arrays.stream(values()).filter(x -> x.getName().compareToIgnoreCase(value) == 0).findFirst().orElse(null);
    }
}
