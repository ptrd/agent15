package net.luminis.tls;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

class ByteUtilsTest {

    @Test
    void hexStringWithSpaces() {
        byte[] bytes = ByteUtils.hexToBytes(" ab cd ef ");
        assertThat(bytes).isEqualTo(new byte[] { (byte) 0xab, (byte) 0xcd, (byte) 0xef });
    }

}