/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.intel.chimera.cipher;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Properties;
import javax.xml.bind.DatatypeConverter;

import com.intel.chimera.conf.ConfigurationKeys;
import com.intel.chimera.utils.ReflectionUtils;
import com.intel.chimera.utils.Utils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public abstract class AbstractCipherTest {

  // data
  public static final int BYTEBUFFER_SIZE = 1000;
  public String[] cipherTests = null;
  Properties props = null;
  String cipherClass = null;
  CipherTransformation[] transformations = null;

  Cipher enc, dec;

  @Before
  public void setup() {
    init();
    Utils.checkNotNull(cipherClass);
    Utils.checkNotNull(transformations);
    props = new Properties();
    props.setProperty(ConfigurationKeys.CHIMERA_CRYPTO_CIPHER_CLASSES_KEY,
        cipherClass);
  }

  protected abstract void init() ;

  @Test
  public void cryptoTest() throws GeneralSecurityException, IOException {
    for (CipherTransformation tran : transformations) {
      cipherTests = TestData.getTestData(tran);
      for (int i = 0; i != cipherTests.length; i += 5) {
        byte[] key = DatatypeConverter.parseHexBinary(cipherTests[i + 1]);
        byte[] iv = DatatypeConverter.parseHexBinary(cipherTests[i + 2]);

        byte[] inputBytes = DatatypeConverter.parseHexBinary(cipherTests[i + 3]);
        byte[] outputBytes = DatatypeConverter.parseHexBinary(cipherTests[i + 4]);

        ByteBuffer inputBuffer = ByteBuffer.allocateDirect(inputBytes.length);
        ByteBuffer outputBuffer = ByteBuffer.allocateDirect(outputBytes.length);
        inputBuffer.put(inputBytes);
        inputBuffer.flip();
        outputBuffer.put(outputBytes);
        outputBuffer.flip();

        ByteBuffer inputBufferHeap = ByteBuffer.allocate(inputBytes.length);
        ByteBuffer outputBufferHeap = ByteBuffer.allocate(outputBytes.length);
        inputBufferHeap.put(inputBytes);
        inputBufferHeap.flip();
        outputBufferHeap.put(outputBytes);
        outputBufferHeap.flip();

        byteBufferTest(tran, key, iv, inputBuffer, outputBuffer, true);
        byteBufferTest(tran, key, iv, inputBufferHeap, outputBufferHeap, false);
        byteArrayTest(tran, key, iv, inputBytes, outputBytes);
      }
    }
  }

  private void byteBufferTest(CipherTransformation transformation, byte[] key, byte[] iv,
      ByteBuffer input, ByteBuffer output, boolean isDirect) throws
      GeneralSecurityException, IOException {
    ByteBuffer decResult, encResult;
    if (isDirect) {
      encResult = ByteBuffer.allocateDirect(BYTEBUFFER_SIZE);
      decResult = ByteBuffer.allocateDirect(BYTEBUFFER_SIZE);
    } else {
      encResult = ByteBuffer.allocate(BYTEBUFFER_SIZE);
      decResult = ByteBuffer.allocate(BYTEBUFFER_SIZE);
    }

    resetCipher(transformation, key, iv);

    //
    // encryption pass
    //
    enc.doFinal(input, encResult);
    input.flip();
    encResult.flip();
    if (!output.equals(encResult)) {
      byte[] b = new byte[output.remaining()];
      output.get(b);
      byte[] c = new byte[encResult.remaining()];
      encResult.get(c);
      Assert.fail("AES failed encryption - expected " + new String(
          DatatypeConverter
              .printHexBinary(b)) + " got " + new String(
          DatatypeConverter.printHexBinary(c)));
    }

    //
    // decryption pass
    //
    dec.doFinal(encResult, decResult);
    decResult.flip();

    if (!input.equals(decResult)) {
      byte[] inArray = new byte[input.remaining()];
      byte[] decResultArray = new byte[decResult.remaining()];
      input.get(inArray);
      decResult.get(decResultArray);
      Assert.fail();
    }
  }

  private void byteArrayTest(CipherTransformation transformation, byte[] key,
      byte[] iv, byte[] input, byte[] output) throws GeneralSecurityException {
    resetCipher(transformation, key, iv);

    byte[] cipherText = enc.doFinal(input, 0, input.length);
    Assert.assertArrayEquals("byte array encryption error.", output, cipherText);

    byte[] plainText = dec.doFinal(cipherText, 0, cipherText.length);
    Assert.assertArrayEquals("byte array decryption error.", input, plainText);
  }

  private void resetCipher(CipherTransformation transformation, byte[] key, byte[] iv) {
    enc = getCipher(transformation);
    dec = getCipher(transformation);

    try {
      enc.init(Cipher.ENCRYPT_MODE, key, iv);
    } catch (Exception e) {
      Assert.fail("AES failed initialisation - " + e.toString());
    }

    try {
      dec.init(Cipher.DECRYPT_MODE, key, iv);
    } catch (Exception e) {
      Assert.fail("AES failed initialisation - " + e.toString());
    }
  }

  private Cipher getCipher(CipherTransformation transformation) {
    try {
      return (Cipher) ReflectionUtils
          .newInstance(ReflectionUtils.getClassByName(cipherClass), props,
              transformation);
    } catch (ClassNotFoundException e) {
      throw new RuntimeException(e);
    }

  }
}