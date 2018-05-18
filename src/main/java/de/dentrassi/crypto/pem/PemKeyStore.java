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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

public class PemKeyStore extends KeyStoreSpi {

	private Map<String, Object> objects = Collections.emptyMap();

	@Override
	public Key engineGetKey(final String alias, final char[] password)
			throws NoSuchAlgorithmException, UnrecoverableKeyException {
		return null;
	}

	@Override
	public Certificate[] engineGetCertificateChain(final String alias) {
		return null;
	}

	@Override
	public Certificate engineGetCertificate(final String alias) {
		final Object obj = this.objects.get(alias);

		if (obj instanceof Certificate) {
			return (Certificate) obj;
		}

		return null;
	}

	@Override
	public Date engineGetCreationDate(final String alias) {
		final Object obj = this.objects.get(alias);

		if (obj instanceof X509Certificate) {
			final X509Certificate xcert = (X509Certificate) obj;
			return xcert.getNotBefore();
		}

		return null;
	}

	@Override
	public void engineSetKeyEntry(final String alias, final Key key, final char[] password, final Certificate[] chain)
			throws KeyStoreException {
		throw new KeyStoreException("Unsupported operation");
	}

	@Override
	public void engineSetKeyEntry(final String alias, final byte[] key, final Certificate[] chain)
			throws KeyStoreException {
		throw new KeyStoreException("Unsupported operation");
	}

	@Override
	public void engineSetCertificateEntry(final String alias, final Certificate cert) throws KeyStoreException {
		throw new KeyStoreException("Unsupported operation");
	}

	@Override
	public void engineDeleteEntry(final String alias) throws KeyStoreException {
		throw new KeyStoreException("Unsupported operation");
	}

	@Override
	public Enumeration<String> engineAliases() {
		final Iterator<String> keys = this.objects.keySet().iterator();

		return new Enumeration<String>() {

			@Override
			public String nextElement() {
				return keys.next();
			}

			@Override
			public boolean hasMoreElements() {
				return keys.hasNext();
			}
		};
	}

	@Override
	public boolean engineContainsAlias(final String alias) {
		return this.objects.containsKey(alias);
	}

	@Override
	public int engineSize() {
		return this.objects.size();
	}

	@Override
	public boolean engineIsKeyEntry(final String alias) {
		return false;
	}

	@Override
	public boolean engineIsCertificateEntry(final String alias) {
		return this.objects.get(alias) instanceof X509Certificate;
	}

	@Override
	public String engineGetCertificateAlias(final Certificate cert) {
		if (!(cert instanceof X509Certificate)) {
			return null;
		}

		for (final Map.Entry<String, Object> entry : this.objects.entrySet()) {
			if (entry.getValue() == cert) {
				return entry.getKey();
			}
		}

		return null;
	}

	@Override
	public void engineStore(final OutputStream stream, final char[] password)
			throws IOException, NoSuchAlgorithmException, CertificateException {

		throw new IOException("Unsupported operation");
	}

	@Override
	public void engineLoad(final InputStream stream, final char[] password)
			throws IOException, NoSuchAlgorithmException, CertificateException {

		if (stream == null) {
			throw new IOException("KeyStore requires input stream");
		}

		final CertificateFactory factory = CertificateFactory.getInstance("X.509");

		@SuppressWarnings("resource")
		final PemReader reader = new PemReader(new InputStreamReader(stream, StandardCharsets.UTF_8));

		final Map<String, Object> objects = new HashMap<>();

		int certIndex = 0;

		PemObject pem;
		while ((pem = reader.readPemObject()) != null) {

			if ("CERTIFICATE".equals(pem.getType())) {

				for (final Certificate cert : factory
						.generateCertificates(new ByteArrayInputStream(pem.getContent()))) {

					if (!(cert instanceof X509Certificate)) {
						continue;
					}

					objects.put("cert-" + certIndex, cert);
					certIndex++;
				}

			}

		}

		this.objects = Collections.unmodifiableMap(objects);

	}

}
