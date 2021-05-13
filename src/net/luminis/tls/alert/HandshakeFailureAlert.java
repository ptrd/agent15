package net.luminis.tls.alert;

import net.luminis.tls.TlsConstants;

public class HandshakeFailureAlert extends ErrorAlert {

    public HandshakeFailureAlert(String message) {
        super(message, TlsConstants.AlertDescription.handshake_failure);
    }
}

