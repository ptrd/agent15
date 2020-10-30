package net.luminis.tls;

import net.luminis.tls.extension.*;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public abstract class HandshakeMessage extends Message {

    public abstract TlsConstants.HandshakeType getType();

    protected int parseHandshakeHeader(ByteBuffer buffer, TlsConstants.HandshakeType expectedType, int minimumMessageSize) throws DecodeErrorException {
        if (buffer.remaining() < 4) {
            throw new DecodeErrorException("handshake message underflow");
        }
        int handshakeType = buffer.get() & 0xff;
        if (handshakeType != expectedType.value) {
            throw new IllegalStateException();  // i.e. programming error
        }
        int messageDataLength = ((buffer.get() & 0xff) << 16) | ((buffer.get() & 0xff) << 8) | (buffer.get() & 0xff);
        if (4 + messageDataLength < minimumMessageSize) {
            throw new DecodeErrorException(getClass().getSimpleName() + " can't be less than " + minimumMessageSize + " bytes");
        }
        if (buffer.remaining() < messageDataLength) {
            throw new DecodeErrorException("handshake message underflow");
        }
        return messageDataLength;
    }

    public abstract byte[] getBytes();

    static List<Extension> parseExtensions(ByteBuffer buffer, TlsConstants.HandshakeType context) throws TlsProtocolException {
        return parseExtensions(buffer, context, null);
    }

    static List<Extension> parseExtensions(ByteBuffer buffer, TlsConstants.HandshakeType context, ExtensionParser customExtensionParser) throws TlsProtocolException {
        if (buffer.remaining() < 2) {
            throw new DecodeErrorException("Extension field must be at least 2 bytes long");
        }
        List<Extension> extensions = new ArrayList<>();

        int extensionsLength = buffer.getShort() & 0xffff;
        if (buffer.remaining() < extensionsLength) {
            throw new DecodeErrorException("Extensions too short");
        }

        if (extensionsLength > 0) {
            int startPosition = buffer.position();

            while (buffer.position() - startPosition < extensionsLength) {
                buffer.mark();
                int extensionType = buffer.getShort() & 0xffff;
                buffer.reset();

                if (extensionType == TlsConstants.ExtensionType.server_name.value) {
                    extensions.add(new ServerNameExtension(buffer));
                }
                else if (extensionType == TlsConstants.ExtensionType.supported_groups.value) {
                    extensions.add(new SupportedGroupsExtension(buffer));
                }
                else if (extensionType == TlsConstants.ExtensionType.signature_algorithms.value) {
                    extensions.add(new SignatureAlgorithmsExtension(buffer));
                }
                else if (extensionType == TlsConstants.ExtensionType.application_layer_protocol_negotiation.value) {
                    extensions.add(new ApplicationLayerProtocolNegotiationExtension().parse(buffer));
                }
                else if (extensionType == TlsConstants.ExtensionType.pre_shared_key.value) {
                    extensions.add(new ServerPreSharedKeyExtension().parse(buffer));
                }
                else if (extensionType == TlsConstants.ExtensionType.early_data.value) {
                    extensions.add(new EarlyDataExtension().parse(buffer));
                }
                else if (extensionType == TlsConstants.ExtensionType.supported_versions.value) {
                    extensions.add(new SupportedVersionsExtension(buffer, context));
                }
                else if (extensionType == TlsConstants.ExtensionType.psk_key_exchange_modes.value) {
                    extensions.add(new PskKeyExchangeModesExtension(buffer));
                }
                else if (extensionType == TlsConstants.ExtensionType.key_share.value) {
                    extensions.add(new KeyShareExtension(buffer, context));
                }
                else {
                    Extension extension = null;
                    if (customExtensionParser != null) {
                        extension = customExtensionParser.apply(buffer, context);
                    }
                    if (extension != null) {
                        extensions.add(extension);
                    }
                    else {
                        Logger.debug("Unsupported extension, type is: " + extensionType);
                        extensions.add(new UnknownExtension().parse(buffer));
                    }
                }
            }
        }
        return extensions;
    }


}
