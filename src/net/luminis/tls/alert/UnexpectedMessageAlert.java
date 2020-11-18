package net.luminis.tls.alert;

import net.luminis.tls.TlsConstants;

public class UnexpectedMessageAlert extends ErrorAlert {

    public UnexpectedMessageAlert(String message) {
        super(message, TlsConstants.AlertDescription.unexpected_message);
    }
}
