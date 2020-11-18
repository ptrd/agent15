package net.luminis.tls.alert;

import net.luminis.tls.TlsConstants;

public class UnsupportedExtensionAlert extends ErrorAlert {

    public UnsupportedExtensionAlert(String message) {
        super(message, TlsConstants.AlertDescription.unsupported_extension);
    }
}
