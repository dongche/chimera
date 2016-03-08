package com.intel.chimera.bytes;

import com.intel.chimera.cipher.CipherTransformation;
import com.intel.chimera.cipher.JceCipher;
import com.intel.chimera.cipher.OpensslCipher;
import com.intel.chimera.cipher.TestData;
import com.intel.chimera.conf.ConfigurationKeys;
import org.junit.After;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import javax.xml.bind.DatatypeConverter;
import java.nio.ByteBuffer;
import java.util.Properties;

/**
 * Unit tests for data encryption / decryption by {@link BytesEncryptor} / {@link BytesDecryptor}.
 */
public class BytesCipherTest {
  Properties properties = new Properties();
  CipherTransformation transformation;
  byte[] key;
  byte[] iv;
  BytesEncryptor encryptor;
  BytesDecryptor decryptor;

  @After
  public void after() {
    properties.clear();
  }

  @Test
  public void jceTest() throws Exception {
    properties.setProperty(ConfigurationKeys.CHIMERA_CRYPTO_CIPHER_CLASSES_KEY,
        JceCipher.class.getName());
    runEachRecord();
  }

  @Test
  public void opensslTest() throws Exception {
    properties.setProperty(ConfigurationKeys.CHIMERA_CRYPTO_CIPHER_CLASSES_KEY,
        OpensslCipher.class.getName());
    runEachRecord();
  }

  private void runEachRecord() throws Exception {
    for (CipherTransformation transformation : CipherTransformation.values()) {
      String[] testData = TestData.getTestData(transformation);
      for (int i = 0; i != testData.length; i += 5) {
        byte[] input = DatatypeConverter.parseHexBinary(testData[i + 3]);
        byte[] output = DatatypeConverter.parseHexBinary(testData[i + 4]);
        this.transformation = transformation;
        key = DatatypeConverter.parseHexBinary(testData[i + 1]);
        iv = DatatypeConverter.parseHexBinary(testData[i + 2]);
        verifyDataTransformation(input, output);
      }
    }
  }

  private void verifyDataTransformation(byte[] input, byte[] output) throws Exception {
    // byte array, doFinal
    resetCipher();
    byte[] cipherText = encryptor.doFinal(input, 0, input.length);
    Assert.assertArrayEquals("bytes encryption error.", output, cipherText);

    byte[] plainText = decryptor.doFinal(cipherText, 0, cipherText.length);
    Assert.assertArrayEquals("bytes decryption error.", input, plainText);

    // byte array, update
    //TODO(dong): padding or not will impact the update result. Differ the cases.
//    resetCipher();
//    cipherText = encryptor.update(input, 0, input.length);
//    Assert.assertArrayEquals("bytes encryption error.", output, cipherText);
//
//    plainText = decryptor.update(cipherText, 0, cipherText.length);
//    Assert.assertArrayEquals("bytes decryption error.", input, plainText);

    // byte buffer, doFinal
    resetCipher();
    ByteBuffer inputBuffer = ByteBuffer.allocateDirect(input.length);
    ByteBuffer outputBuffer = ByteBuffer.allocateDirect(output.length);
    inputBuffer.put(input);
    inputBuffer.flip();
    outputBuffer.put(output);
    outputBuffer.flip();

    ByteBuffer cipherTextBuffer = ByteBuffer.allocateDirect(input.length + 16);
    encryptor.doFinal(inputBuffer, cipherTextBuffer);
    inputBuffer.flip();
    cipherTextBuffer.flip();
    Assert.assertTrue(cipherTextBuffer.equals(outputBuffer));

    ByteBuffer plainTextBuffer = ByteBuffer.allocateDirect(output.length);
    decryptor.doFinal(cipherTextBuffer, plainTextBuffer);
    cipherTextBuffer.flip();
    plainTextBuffer.flip();
    Assert.assertTrue(plainTextBuffer.equals(inputBuffer));

    // byte buffer, update
    // ...
  }

  private void resetCipher() throws Exception {
    encryptor = new BytesEncryptor(transformation, properties, key, iv);
    decryptor = new BytesDecryptor(transformation, properties, key, iv);
  }
}
