package net.luminis.tls.alert;

import net.luminis.tls.TlsConstants;

public class IllegalParameterAlert extends ErrorAlert {

    public IllegalParameterAlert(String message) {
        super(message, TlsConstants.AlertDescription.illegal_parameter);
    }
}
