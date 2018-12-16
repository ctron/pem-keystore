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
import java.security.cert.CertificateException;
import java.util.Map;

public class PemConfigKeyStore extends AbstractPemKeyStore {

	@Override
	protected Map<String, Entry> load(final InputStream stream) throws CertificateException, IOException {
		return PemUtils.loadFromConfiguration(stream);
	}

}
