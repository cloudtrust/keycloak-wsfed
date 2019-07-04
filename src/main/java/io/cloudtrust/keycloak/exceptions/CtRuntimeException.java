package io.cloudtrust.keycloak.exceptions;

public class CtRuntimeException extends RuntimeException {
    private static final long serialVersionUID = 4877237030143597244L;

    public CtRuntimeException(String message) {
        super(message);
    }

    public CtRuntimeException(Throwable cause) {
        super(cause);
    }
}
