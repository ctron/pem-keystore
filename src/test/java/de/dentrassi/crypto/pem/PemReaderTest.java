/*******************************************************************************
 * Copyright (c) 2024 Red Hat Inc and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     Domenico Francesco Bruscino - initial PemReader implementation
 *******************************************************************************/

package de.dentrassi.crypto.pem;

import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

public class PemReaderTest {

   private static final String TEST_TEXT = "TEST";

   @Test
   public void testCertificate() throws Exception {
      try (PemReader pemReader = new PemReader(new InputStreamReader(PemReaderTest.class.getResourceAsStream("/test1.crt")))) {
         Certificate certificate = (Certificate) pemReader.readObject();
         Assertions.assertTrue(certificate instanceof X509Certificate);
         Assertions.assertEquals("CN=Test 1", ((X509Certificate)certificate).getSubjectX500Principal().getName());
      }
   }

   @Test
   public void testCertificateChain() throws Exception {
      try (PemReader pemReader = new PemReader(new InputStreamReader(PemReaderTest.class.getResourceAsStream("/tls.crt")))) {
         Certificate cert1 = (Certificate) pemReader.readObject();
         Assertions.assertTrue(cert1 instanceof X509Certificate);
         Assertions.assertEquals("CN=Test 1", ((X509Certificate)cert1).getSubjectX500Principal().getName());

         Certificate cert2 = (Certificate) pemReader.readObject();
         Assertions.assertTrue(cert2 instanceof X509Certificate);
         Assertions.assertEquals("CN=Intermediate", ((X509Certificate)cert2).getSubjectX500Principal().getName());

         Certificate cert3 = (Certificate) pemReader.readObject();
         Assertions.assertTrue(cert3 instanceof X509Certificate);
         Assertions.assertEquals("CN=CA", ((X509Certificate)cert3).getSubjectX500Principal().getName());

         CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
         CertPath certPath = certificateFactory.generateCertPath(Arrays.asList(cert1, cert2));
         TrustAnchor anchor = new TrustAnchor((X509Certificate)cert3, null);

         CertPathValidator validator = CertPathValidator.getInstance("PKIX");
         PKIXParameters params = new PKIXParameters(Collections.singleton(anchor));
         params.setRevocationEnabled(false);
         PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) validator.validate(certPath, params);
         Assertions.assertEquals(cert3, result.getTrustAnchor().getTrustedCert());
      }
   }

   @Test
   public void testECPrivateKey() throws Exception {
      try (PemReader pemReader = new PemReader(new InputStreamReader(PemReaderTest.class.getResourceAsStream("/ec-private-key.pem")))) {
         KeyPair keyPair = (KeyPair) pemReader.readObject();
         testSignature("SHA512withECDSA", keyPair);
      }
   }

   @Test
   public void testDSAPrivateKey() throws Exception {
      try (PemReader pemReader = new PemReader(new InputStreamReader(PemReaderTest.class.getResourceAsStream("/dsa-private-key.pem")))) {
         KeyPair keyPair = (KeyPair) pemReader.readObject();
         testSignature("SHA512WithDSA", keyPair);
      }
   }

   @Test
   public void testRSAPrivateKey() throws Exception {
      try (PemReader pemReader = new PemReader(new InputStreamReader(PemReaderTest.class.getResourceAsStream("/privkey1.pem")))) {
         KeyPair keyPair = (KeyPair) pemReader.readObject();
         testSignature("SHA512WithRSA", keyPair);
      }
   }

   @Test
   public void testPrivateKey() throws Exception {
      try (PemReader pemReader = new PemReader(new InputStreamReader(PemReaderTest.class.getResourceAsStream("/private-key.pem")))) {
         Assertions.assertTrue(pemReader.readObject() instanceof PrivateKey);
      }
   }

   private void testSignature(String algorithm, KeyPair keyPair) throws Exception {
      Assumptions.assumeTrue(() -> {
         try {
            Signature.getInstance(algorithm);
         } catch (Throwable t) {
            return t == null;
         }
         return true;
      }, "Cannot find any provider supporting " + algorithm);

      byte[] messageBytes = TEST_TEXT.getBytes(StandardCharsets.UTF_8);

      Signature signer = Signature.getInstance(algorithm);
      signer.initSign(keyPair.getPrivate());
      signer.update(messageBytes);
      byte[] signature = signer.sign();

      Signature verifier = Signature.getInstance(algorithm);
      verifier.initVerify(keyPair.getPublic());
      verifier.update(messageBytes);
      Assertions.assertTrue(verifier.verify(signature));
   }
}
