package net.luminis.tls.alert;

import net.luminis.tls.TlsConstants;

public class DecryptErrorAlert extends ErrorAlert {

    public DecryptErrorAlert(String message) {
        super(message, TlsConstants.AlertDescription.decrypt_error);
    }
}
