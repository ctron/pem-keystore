package de.dentrassi.crypto.pem;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey;
import org.junit.Assert;
import org.junit.jupiter.api.Test;

public class LetsEncryptPemCertificateTest {

	@Test
	public void testLetsEncryptPemCertificateTest() throws Exception {

		final KeyStore ks = KeyStore.getInstance("PEMCFG", new PemKeyStoreProvider());
		try (FileInputStream stream = new FileInputStream("src/test/resources/pem_tls.properties")) {
			ks.load(stream, new char[0]);
		}
		java.security.cert.Certificate cert = ks.getCertificate("letsencrypt");
		X509Certificate x509 = (X509Certificate) cert;
		Key key = ks.getKey("letsencrypt", new char[0]);
		assertEquals(x509.getSubjectAlternativeNames().size(), 2);
		assertNotNull(key);
		assertEquals(key.getClass(), BCRSAPrivateCrtKey.class);
		Certificate[] chain = ks.getCertificateChain("letsencrypt");
		assertNotNull(chain);
		Assert.assertEquals(2, chain.length);
	}
}
