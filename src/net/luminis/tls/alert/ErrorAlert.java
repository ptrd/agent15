package net.luminis.tls.alert;

import net.luminis.tls.TlsConstants;
import net.luminis.tls.TlsProtocolException;

public abstract class ErrorAlert extends TlsProtocolException {

    private final TlsConstants.AlertDescription alert;

    public ErrorAlert(String message, TlsConstants.AlertDescription alert) {
        super(message);
        this.alert = alert;
    }

    public TlsConstants.AlertDescription alertDescription() {
        return alert;
    }
}
