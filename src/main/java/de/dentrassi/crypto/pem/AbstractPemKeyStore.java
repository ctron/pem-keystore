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

import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Optional;

public abstract class AbstractPemKeyStore extends AbstractReadOnlyKeyStore {

	public static final class Entry {

		private final Key			key;
		private final Certificate[]	certificateChain;

		public Entry() {
			this(null, null);
		}

		public Entry(final Key key, final Certificate[] certificateChain) {
			this.key = key;

			if (certificateChain != null && certificateChain.length > 0) {
				this.certificateChain = certificateChain;
			} else {
				this.certificateChain = null;
			}
		}

		public Key getKey() {
			return this.key;
		}

		public boolean isKey() {
			return this.key != null;
		}

		public Certificate[] getCertificateChain() {
			if (this.certificateChain == null) {
				return null;
			}
			return this.certificateChain.clone();
		}

		public Certificate getCertificate() {
			if (this.certificateChain == null) {
				return null;
			}
			return this.certificateChain[0];
		}

		public boolean isCertificate() {
			return this.certificateChain != null;
		}

		public Entry merge(final Entry other) {

			if (other == null) {
				return this;
			}

			Key key = other.key;
			Certificate[] certificateChain = other.certificateChain;

			if (key == null) {
				key = this.key;
			}
			if (certificateChain == null) {
				certificateChain = this.certificateChain;
			}

			return new Entry(key, certificateChain);
		}
	}

	private Map<String, Entry> entries = new HashMap<>();

	protected abstract Map<String, Entry> load(InputStream stream) throws IOException, NoSuchAlgorithmException, CertificateException;

	protected Optional<Entry> getEntry(final String alias) {
		return Optional.of(this.entries.get(alias));
	}

	@Override
	public void engineSetKeyEntry(final String alias, final Key key, final char[] password, final Certificate[] chain) throws KeyStoreException {
		Entry entry = new Entry(key, chain);
		this.entries.put(alias, entry);
	}

	@Override
	public Key engineGetKey(final String alias, final char[] password) {

		return getEntry(alias).map(Entry::getKey).orElse(null);

	}

	@Override
	public boolean engineIsKeyEntry(final String alias) {

		return getEntry(alias).map(Entry::isKey).orElse(false);

	}

	@Override
	public Certificate[] engineGetCertificateChain(final String alias) {

		return getEntry(alias).map(Entry::getCertificateChain).orElse(null);

	}

	@Override
	public Certificate engineGetCertificate(final String alias) {

		return getEntry(alias).map(Entry::getCertificate).orElse(null);

	}

	@Override
	public Date engineGetCreationDate(final String alias) {

		return getEntry(alias).map(Entry::getCertificate).map(cert -> cert instanceof X509Certificate ? (X509Certificate) cert : null).map(X509Certificate::getNotBefore).orElse(null);

	}

	@Override
	public Enumeration<String> engineAliases() {
		final Iterator<String> keys = this.entries.keySet().iterator();

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
		return this.entries.containsKey(alias);
	}

	@Override
	public int engineSize() {
		return this.entries.size();
	}

	@Override
	public boolean engineIsCertificateEntry(final String alias) {

		return getEntry(alias).map(Entry::isCertificate).orElse(null);

	}

	@Override
	public String engineGetCertificateAlias(final Certificate cert) {

		if (!(cert instanceof Certificate)) {
			return null;
		}

		for (final Map.Entry<String, Entry> entry : this.entries.entrySet()) {

			if (cert == entry.getValue().getCertificate()) {
				return entry.getKey();
			}

		}

		return null;
	}

	@Override
	public void engineLoad(final InputStream stream, final char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {

		// if (stream != null) {
		// this.entries = load(stream);
		// }

		if (stream == null) {
			throw new IOException("KeyStore requires input stream");
		}

		this.entries = load(stream);

	}

}
