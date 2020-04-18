package net.luminis.tls;

import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class ServerHelloTest {

    @Test
    void parseServerHello() throws Exception {
        byte[] data = ByteUtils.hexToBytes("02000077030327303877f58601e5e987b1be085f509adecd10056353daf3843f5f89084a4c6100130100004f002b0002030400330045001700410456517b9551d5ce0950c8210bf1f30b3f5d2b066ac6ac7469d6490387b36d9a57385bdfe2d5d55a1e6956a6d8d771cd7f1aee418b1cf615cbd976ba509a48e9de");

        ServerHello sh = new ServerHello().parse(ByteBuffer.wrap(data), data.length, mock(TlsState.class));
    }

    @Test
    void serializeServerHello() throws Exception {
        ServerHello sh = new ServerHello();
        byte[] serializedData = sh.getBytes();

        assertThat(serializedData).isEqualTo(ByteUtils.hexToBytes(""));
    }

}