/*******************************************************************************
 * Copyright (c) 2018 Red Hat Inc and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     Jens Reimann - initial API and implementation
 *******************************************************************************/

package de.dentrassi.crypto.pem;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManagerFactory;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.google.common.io.ByteSource;

import io.undertow.Undertow;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.util.Headers;

public class UndertowTest {

    @Test
    public void testTls() throws Exception {

        final int port = 8080;

        final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

        final KeyStore ks = KeyStore.getInstance("PEMCFG", new PemKeyStoreProvider());
        try (FileInputStream stream = new FileInputStream("src/test/resources/tls.properties")) {
            ks.load(stream, new char[0]);
        }

        kmf.init(ks, new char[0]);

        final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);

        final Undertow server = Undertow.builder()
                .addHttpsListener(port, "localhost", kmf.getKeyManagers(), tmf.getTrustManagers())
                .setHandler(new HttpHandler() {

                    @Override
                    public void handleRequest(final HttpServerExchange exchange) throws Exception {
                        exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "text/plain");
                        exchange.getResponseSender().send("Foo");
                    }
                })
                .build();

        try {
            server.start();

            final String content = testGet("https://localhost:" + port);
            Assertions.assertEquals("Foo", content);

        } finally {
            server.stop();
        }
    }

    private String testGet(final String url) throws Exception {

        final KeyStore ks = KeyStore.getInstance("PEMCA", new PemKeyStoreProvider());
        try (FileInputStream stream = new FileInputStream("src/test/resources/ca.crt")) {
            ks.load(stream, new char[0]);
        }

        final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);

        final SSLContext ctx = SSLContext.getInstance("TLSv1.2");
        ctx.init(null, tmf.getTrustManagers(), new SecureRandom());

        final HttpsURLConnection con = (HttpsURLConnection) new URL(url).openConnection();
        con.setSSLSocketFactory(ctx.getSocketFactory());
        con.setHostnameVerifier(new HostnameVerifier() {

            @Override
            public boolean verify(final String hostname, final SSLSession session) {
                return true;
            }
        });

        return new ByteSource() {

            @Override
            public InputStream openStream() throws IOException {
                return con.getInputStream();
            }
        }.asCharSource(StandardCharsets.UTF_8).read();

    }

}
