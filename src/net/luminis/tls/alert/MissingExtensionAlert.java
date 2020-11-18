package net.luminis.tls.alert;

import net.luminis.tls.TlsConstants;

public class MissingExtensionAlert extends ErrorAlert {

    public MissingExtensionAlert() {
        super("missing extension", TlsConstants.AlertDescription.missing_extension);
    }

    public MissingExtensionAlert(String message) {
        super(message, TlsConstants.AlertDescription.missing_extension);
    }
}
