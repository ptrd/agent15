package net.luminis.tls.alert;

import net.luminis.tls.TlsConstants;

import java.util.List;
import java.util.stream.Collectors;

public class NoApplicationProtocolAlert extends ErrorAlert
{
    public NoApplicationProtocolAlert() {
        super("unsupported application protocol", TlsConstants.AlertDescription.no_application_protocol);
    }

    public NoApplicationProtocolAlert(List<String> requestedProtocols) {
        super("unsupported application protocol: " + requestedProtocols.stream().collect(Collectors.joining(",")),
                TlsConstants.AlertDescription.no_application_protocol);
    }
}
