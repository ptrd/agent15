package net.luminis.tls.extension;

/**
 * A TLS Extension.
 * See https://tools.ietf.org/html/rfc8446#section-4.2
 */
public abstract class Extension {

    public abstract byte[] getBytes();
}
