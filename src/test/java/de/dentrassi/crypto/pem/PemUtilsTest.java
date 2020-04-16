package de.dentrassi.crypto.pem;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.Map;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class PemUtilsTest {

    @Test
    void loadFromConfigurationClasspath() throws CertificateException, IOException {
        Map<String, AbstractPemKeyStore.Entry> map = PemUtils.loadFromConfiguration(getClass().getResourceAsStream("/classpath_tls.properties"));
        AbstractPemKeyStore.Entry entry = map.get("keycert");
        assertThat(entry.getKey()).isNotNull();
        assertThat(entry.getCertificate()).isNotNull();
    }
}
