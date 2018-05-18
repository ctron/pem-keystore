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

import java.security.KeyStore;
import java.security.Security;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class PemKeyStoreTest {

	@BeforeAll
	public static void setup() {
		Security.addProvider(new PemKeyStoreProvider());
	}

	@Test
	public void testGetInstance1() throws Exception {
		KeyStore.getInstance("PEM", "PEM");
	}

	@Test
	public void testGetInstance2() throws Exception {
		KeyStore.getInstance("PEM");
	}

}
