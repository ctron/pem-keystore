/*******************************************************************************
 * Copyright (c) 2019 Sergio Moreno.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 *Contributors:
 *		Sergio Moreno - Initial implementation
 *******************************************************************************/

package de.dentrassi.crypto.pem.impl;

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Map;

import de.dentrassi.crypto.pem.AbstractMutablePemKeyStore;
import de.dentrassi.crypto.pem.PemUtils;


/**
 * Implementation of {@link AbstractMutablePemKeyStore}
 * 
 * @author Sergio Moreno
 *
 */
public class MutablePemKeyStore extends AbstractMutablePemKeyStore {

	

	@Override
	protected Map<String, Entry> load(InputStream stream) throws IOException, NoSuchAlgorithmException, CertificateException {
		return PemUtils.loadFromConfiguration(stream);
	}

}
