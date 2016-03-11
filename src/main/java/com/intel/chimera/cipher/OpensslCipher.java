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

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

import com.intel.chimera.utils.Utils;

/**
 * Implement the Cipher using JNI into OpenSSL.
 */
public class OpensslCipher implements Cipher {
  private final Properties props;
  private final CipherTransformation transformation;
  private final Openssl cipher;

  // TODO(dong): make it configurable?
  private static final int BUFFER_SIZE = 4 * 1024;
  private ByteBuffer inDirectBuffer = null;
  private ByteBuffer outDirectBuffer = null;

  /**
   * Constructs a {@link com.intel.chimera.cipher.Cipher} using JNI into OpenSSL
   * @param props properties for OpenSSL cipher
   * @param transformation transformation for OpenSSL cipher
   * @throws GeneralSecurityException if OpenSSL cipher initialize failed
   */
  public OpensslCipher(Properties props, CipherTransformation transformation)
      throws GeneralSecurityException {
    this.props = props;
    this.transformation = transformation;

    String loadingFailureReason = Openssl.getLoadingFailureReason();
    if (loadingFailureReason != null) {
      throw new RuntimeException(loadingFailureReason);
    }

    cipher = Openssl.getInstance(transformation.getName());
  }

  @Override
  public CipherTransformation getTransformation() {
    return transformation;
  }

  @Override
  public Properties getProperties() {
    return props;
  }

  /**
   * Initializes the cipher with mode, key and iv.
   * @param mode {@link #ENCRYPT_MODE} or {@link #DECRYPT_MODE}
   * @param key crypto key for the cipher
   * @param iv Initialization vector for the cipher
   * @throws IOException if cipher initialize fails
   */
  @Override
  public void init(int mode, byte[] key, byte[] iv) {
    Utils.checkNotNull(key);
    Utils.checkNotNull(iv);

    int cipherMode = Openssl.DECRYPT_MODE;
    if (mode == ENCRYPT_MODE)
      cipherMode = Openssl.ENCRYPT_MODE;

    cipher.init(cipherMode, key, iv);
  }

  /**
   * Continues a multiple-part encryption/decryption operation. The data
   * is encrypted or decrypted, depending on how this cipher was initialized.
   * @param inBuffer the input ByteBuffer
   * @param outBuffer the output ByteBuffer
   * @return int number of bytes stored in <code>output</code>
   * @throws ShortBufferException if there is insufficient space
   * in the output buffer
   */
  @Override
  public int update(ByteBuffer inBuffer, ByteBuffer outBuffer)
      throws ShortBufferException {
    // TODO(dong): handle non direct ByteBuffer
    return cipher.update(inBuffer, outBuffer);
  }

  /**
   * Continues a multiple-part encryption/decryption operation. The data
   * is encrypted or decrypted, depending on how this cipher was initialized.
   *
   * @param input the input byte array
   * @param offset the offset in input where the input starts
   * @param len the input length
   * @return the new encrypted/decrypted byte array.
   */
  @Override
  public byte[] update(byte[] input, int offset, int len) {
    if (inDirectBuffer == null) {
      inDirectBuffer = ByteBuffer.allocateDirect(BUFFER_SIZE);
    }
    if (outDirectBuffer == null) {
      outDirectBuffer = ByteBuffer.allocateDirect(BUFFER_SIZE + transformation.getAlgorithmBlockSize());
    }

    int estimatedOutputLen = estimateUpdateOutputSize(len);
    byte[] estimatedOutput = new byte[estimatedOutputLen];
    int outputLen = 0;
    byte[] output = null;
    int cursor = 0;

    // loop to update BUFFER_SIZE block
    while (len > BUFFER_SIZE) {
      updateSlice(input, offset, BUFFER_SIZE);

      int outputSliceLength = outDirectBuffer.remaining();
      outDirectBuffer.get(estimatedOutput, cursor, outputSliceLength);

      cursor += outputSliceLength;
      len -= BUFFER_SIZE;
      offset += BUFFER_SIZE;
    }

    // handle the last piece of block
    updateSlice(input, offset, len);
    int outputSliceLength = outDirectBuffer.remaining();
    outputLen = cursor + outputSliceLength;

    if (outputLen == estimatedOutputLen) {
      outDirectBuffer.get(estimatedOutput, cursor, outputSliceLength);
      output = estimatedOutput;
    } else {
      output = new byte[outputLen];
      System.arraycopy(estimatedOutput, 0, output, 0, cursor);
      outDirectBuffer.get(output, cursor, outputSliceLength);
    }

    return output;
  }

  private int estimateUpdateOutputSize(int inputSize) {
    /**
     * TODO(dong): The output size differ a lot based on
     * 1. transformation mode
     * 2. encryption or decryption
     * The size should be estimated case by case.
     *
     * For simplicity now, use downward aligned input size, which covers the most.
     */

    return inputSize - inputSize % transformation.getAlgorithmBlockSize();
  }

  private void updateSlice(byte[] input, int offset, int len) {
    inDirectBuffer.clear();
    inDirectBuffer.put(input, offset, len);
    inDirectBuffer.flip();

    outDirectBuffer.clear();

    try {
      update(inDirectBuffer, outDirectBuffer);
    } catch (ShortBufferException e) {
      // this cannot happen.
    }

    outDirectBuffer.flip();
  }

  /**
   * Encrypts or decrypts data in a single-part operation, or finishes a
   * multiple-part operation. The data is encrypted or decrypted, depending
   * on how this cipher was initialized.
   * @param inBuffer the input ByteBuffer
   * @param outBuffer the output ByteBuffer
   * @return int number of bytes stored in <code>output</code>
   * @throws BadPaddingException if this cipher is in decryption mode,
   * and (un)padding has been requested, but the decrypted data is not
   * bounded by the appropriate padding bytes
   * @throws IllegalBlockSizeException if this cipher is a block cipher,
   * no padding has been requested (only in encryption mode), and the total
   * input length of the data processed by this cipher is not a multiple of
   * block size; or if this encryption algorithm is unable to
   * process the input data provided.
   * @throws ShortBufferException if the given output buffer is too small
   * to hold the result
   */
  @Override
  public int doFinal(ByteBuffer inBuffer, ByteBuffer outBuffer)
      throws ShortBufferException, IllegalBlockSizeException,
      BadPaddingException {
    // TODO(dong): handle non direct ByteBuffer
    int n = cipher.update(inBuffer, outBuffer);
    return n + cipher.doFinal(outBuffer);
  }

  /**
   * Encrypts or decrypts data in a single-part operation, or finishes a
   * multiple-part operation.
   *
   * @param input the input byte array
   * @param offset the offset in input where the input starts
   * @param len the input length
   * @return the new encrypted/decrypted byte array
   * @throws BadPaddingException if this cipher is in decryption mode,
   * and (un)padding has been requested, but the decrypted data is not
   * bounded by the appropriate padding bytes
   * @throws IllegalBlockSizeException if this cipher is a block cipher,
   * no padding has been requested (only in encryption mode), and the total
   * input length of the data processed by this cipher is not a multiple of
   * block size; or if this encryption algorithm is unable to
   * process the input data provided.
   */
  @Override
  public byte[] doFinal(byte[] input, int offset, int len)
      throws IllegalBlockSizeException, BadPaddingException {
    if (inDirectBuffer == null) {
      inDirectBuffer = ByteBuffer.allocateDirect(BUFFER_SIZE);
    }
    if (outDirectBuffer == null) {
      outDirectBuffer = ByteBuffer.allocateDirect(BUFFER_SIZE + transformation.getAlgorithmBlockSize());
    }

    int estimatedOutputLen = estimateFinalOutputSize(len);
    byte[] estimatedOutput = new byte[estimatedOutputLen];
    int outputLen = 0;
    byte[] output = null;
    int cursor = 0;

    // loop to update BUFFER_SIZE block
    while (len > BUFFER_SIZE) {
      updateSlice(input, offset, BUFFER_SIZE);

      int outputSliceLength = outDirectBuffer.remaining();
      outDirectBuffer.get(estimatedOutput, cursor, outputSliceLength);

      cursor += outputSliceLength;
      len -= BUFFER_SIZE;
      offset += BUFFER_SIZE;
    }

    // handle the last piece of block
    inDirectBuffer.clear();
    inDirectBuffer.put(input, offset, len);
    inDirectBuffer.flip();

    outDirectBuffer.clear();

    try {
      doFinal(inDirectBuffer, outDirectBuffer);
    } catch (ShortBufferException e) {
      // this cannot happen.
    }

    outDirectBuffer.flip();

    int outputSliceLength = outDirectBuffer.remaining();
    outputLen = cursor + outputSliceLength;

    if (outputLen == estimatedOutputLen) {
      outDirectBuffer.get(estimatedOutput, cursor, outputSliceLength);
      output = estimatedOutput;
    } else {
      output = new byte[outputLen];
      System.arraycopy(estimatedOutput, 0, output, 0, cursor);
      outDirectBuffer.get(output, cursor, outputSliceLength);
    }

    return output;
  }

  private int estimateFinalOutputSize(int inputSize) {
    /**
     * TODO(dong): the same problem as {@link OpensslCipher#estimateUpdateOutputSize(int)}
     *
     * For simplicity now, use upward aligned input size, which cover the most.
     */
    return inputSize - inputSize % transformation.getAlgorithmBlockSize()
        + transformation.getAlgorithmBlockSize();
  }

  /**
   * Closes the OpenSSL cipher. Clean the Openssl native context.
   */
  @Override
  public void close() {
    cipher.clean();
  }
}
