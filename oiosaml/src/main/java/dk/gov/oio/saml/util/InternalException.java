package dk.gov.oio.saml.util;

public class InternalException extends Exception {
    private static final long serialVersionUID = -6887665292794106098L;

    public InternalException(String errorMessage) {
        super(errorMessage);
    }

    public InternalException(String errorMessage, Exception exception) {
        super(errorMessage, exception);
    }

    public InternalException(Exception exception) {
        super(exception.getMessage(), exception);
    }
}
