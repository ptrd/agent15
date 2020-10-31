package net.luminis.tls.extension;

import net.luminis.tls.alert.DecodeErrorException;
import net.luminis.tls.extension.ServerNameExtension;
import net.luminis.tls.extension.SignatureAlgorithmsExtension;
import net.luminis.tls.handshake.EncryptedExtensions;
import net.luminis.tls.util.ByteUtils;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.util.List;

import static net.luminis.tls.TlsConstants.SignatureScheme.rsa_pkcs1_sha256;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class EncryptedExtensionsTest {

    @Test
    void parseEmptyEncryptedExtensions() throws Exception {
        //                                         msg type msg lenth  extenions list size
        byte[] data = ByteUtils.hexToBytes("08" +    "000002" + "0000");

        EncryptedExtensions ee = new EncryptedExtensions().parse(ByteBuffer.wrap(data), data.length);
        assertThat(ee.getExtensions()).isEmpty();
    }

    @Test
    void parseEncryptedExtensionsWithIncorrectMsgLength() throws Exception {
        //                                         msg type msg lenth  extenions list size
        byte[] data = ByteUtils.hexToBytes("08" +    "000000" + "00ff");

        assertThatThrownBy(() ->
                new EncryptedExtensions().parse(ByteBuffer.wrap(data), data.length)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseEncryptedExtensionsWithIncorrectExtensionsLength() throws Exception {
        //                                         msg type msg lenth  extenions list size
        byte[] data = ByteUtils.hexToBytes("08" +    "000002" + "00ff");

        assertThatThrownBy(() ->
                new EncryptedExtensions().parse(ByteBuffer.wrap(data), data.length)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void parseEncryptedExtensionsWithIncorrectLengths() throws Exception {
        //                                         msg type msg lenth  extenions list size
        byte[] data = ByteUtils.hexToBytes("08" +    "0000ff" + "00fd");

        assertThatThrownBy(() ->
                new EncryptedExtensions().parse(ByteBuffer.wrap(data), data.length)
        ).isInstanceOf(DecodeErrorException.class);
    }

    @Test
    void serializeEmptyEncryptedExtensions() {
        byte[] data = new EncryptedExtensions().getBytes();

        assertThat(data).isEqualTo(ByteUtils.hexToBytes("08" + "000002" + "0000"));
    }

    @Test
    void serializeEncryptedExtensions() {
        byte[] data = new EncryptedExtensions(List.of(
                new ServerNameExtension("server"),
                new SignatureAlgorithmsExtension(rsa_pkcs1_sha256)
        )).getBytes();

        byte[] expected = ByteUtils.hexToBytes("08" + "000019" + "0017"
                + ByteUtils.bytesToHex(new ServerNameExtension("server").getBytes())
                + ByteUtils.bytesToHex(new SignatureAlgorithmsExtension(rsa_pkcs1_sha256).getBytes()));
        assertThat(data).isEqualTo(expected);
    }

}
