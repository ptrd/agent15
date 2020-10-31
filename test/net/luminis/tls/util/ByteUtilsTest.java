package net.luminis.tls.util;

import net.luminis.tls.util.ByteUtils;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ByteUtilsTest {

    @Test
    void hexStringWithSpaces() {
        byte[] bytes = ByteUtils.hexToBytes(" ab cd ef ");
        assertThat(bytes).isEqualTo(new byte[] { (byte) 0xab, (byte) 0xcd, (byte) 0xef });
    }

}