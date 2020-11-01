package net.luminis.tls.alert;

public class MissingExtensionAlert extends TlsAlertException {

    public MissingExtensionAlert() {
        super("missing extension");
    }

    public MissingExtensionAlert(String message) {
        super(message);
    }
}
