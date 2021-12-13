package dk.gov.oio.saml.util;

public class ExternalException extends Exception {
    private static final long serialVersionUID = 7233074999222868712L;

    public ExternalException(Exception exception) {
        super(exception.getMessage(), exception);
    }

    public ExternalException(String errorMessage) {
        super(errorMessage);
    }

    public ExternalException(String errorMessage, Exception exception) {
        super(errorMessage, exception);
    }
}
