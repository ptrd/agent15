package net.luminis.tls.exception;

public class MissingExtensionAlert extends TlsAlertException {

    public MissingExtensionAlert() {
        super("missing extension");
    }

    public MissingExtensionAlert(String message) {
        super(message);
    }
}
