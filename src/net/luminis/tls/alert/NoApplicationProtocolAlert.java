package net.luminis.tls.alert;

import net.luminis.tls.TlsConstants;

public class NoApplicationProtocolAlert extends ErrorAlert
{
    public NoApplicationProtocolAlert() {
        super("unsupported application protocol", TlsConstants.AlertDescription.no_application_protocol);
    }
}
