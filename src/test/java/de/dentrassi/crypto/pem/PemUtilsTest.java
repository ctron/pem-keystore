/*******************************************************************************
 * Copyright (c) 2020 CarePay International
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     Barry Lagerweij - Added classpath prefix support
 *******************************************************************************/

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

    @Test
    void loadFromConfigurationFile() throws CertificateException, IOException {
        Map<String, AbstractPemKeyStore.Entry> map = PemUtils.loadFromConfiguration(getClass().getResourceAsStream("/file_tls.properties"));
        AbstractPemKeyStore.Entry entry = map.get("keycert");
        assertThat(entry.getKey()).isNotNull();
        assertThat(entry.getCertificate()).isNotNull();
    }
}
