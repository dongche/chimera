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

  /** The size of buffer, which is used for byte array */
  private final int bufferSize;
  /** The buffer used for byte array input */
  private ByteBuffer inBuffer = null;
  /** The buffer used for byte array output */
  private ByteBuffer outBuffer = null;

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
    this.bufferSize = Utils.getCipherBufferSize(props);

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
   * @param input the input ByteBuffer
   * @param output the output ByteBuffer
   * @return int number of bytes stored in <code>output</code>
   * @throws ShortBufferException if there is insufficient space
   * in the output buffer
   */
  @Override
  public int update(ByteBuffer input, ByteBuffer output)
      throws ShortBufferException {
    return cipher.update(input, output);
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
    byte[] output = null;
    try {
      output = updateOrDoFinal(input, offset, len, false);
    } catch (IllegalBlockSizeException ibse) {
      // this cannot happen.
    } catch (BadPaddingException bpe) {
      // this cannot happen.
    } catch (ShortBufferException sbe) {
      // this cannot happen.
    }
    return output;
  }

  /**
   * Encrypts or decrypts data in a single-part operation, or finishes a
   * multiple-part operation. The data is encrypted or decrypted, depending
   * on how this cipher was initialized.
   * @param input the input ByteBuffer
   * @param output the output ByteBuffer
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
  public int doFinal(ByteBuffer input, ByteBuffer output)
      throws ShortBufferException, IllegalBlockSizeException,
      BadPaddingException {
    int n = cipher.update(input, output);
    return n + cipher.doFinal(output);
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
    byte[] output = null;
    try {
      output = updateOrDoFinal(input, offset, len, true);
    } catch (ShortBufferException sbe) {
      // this cannot happen.
    }
    return output;
  }

  /**
   * Closes the OpenSSL cipher. Clean the Openssl native context.
   */
  @Override
  public void close() {
    cipher.clean();
  }

  private byte[] updateOrDoFinal(byte[] input, int offset, int len, boolean isFinal)
      throws IllegalBlockSizeException, BadPaddingException, ShortBufferException {
    allocateBuffer();

    final int blockSize = transformation.getAlgorithmBlockSize();
    int bufferLen = isFinal ? len - len % blockSize + blockSize : len - len % blockSize;
    byte[] buffer = new byte[bufferLen];

    int pos = updateInput(input, offset, len, isFinal, buffer);
    return getOutput(buffer, pos, bufferLen);
  }

  private void allocateBuffer() {
    if (inBuffer == null) {
      inBuffer = ByteBuffer.allocateDirect(bufferSize);
    }
    if (outBuffer == null) {
      outBuffer = ByteBuffer.allocateDirect(bufferSize + transformation.getAlgorithmBlockSize());
    }
  }

  /**
   * Processes input and puts results into output.
   * Firstly processes input blocks which are aligned with the buffer,
   * and put results into output. Then processes the last block and put result into outBuffer.
   */
  private int updateInput(byte[] input, int offset, int len, boolean isFinal, byte[] output)
      throws IllegalBlockSizeException, BadPaddingException, ShortBufferException {
    int outputLen = 0;

    // loop to update (len / bufferSize) blocks
    while (len > bufferSize) {
      updateData(input, offset, bufferSize, false);

      int remaining = outBuffer.remaining();
      outBuffer.get(output, outputLen, remaining);

      outputLen += remaining;
      len -= bufferSize;
      offset += bufferSize;
    }

    // handle the last piece of block
    updateData(input, offset, len, isFinal);
    return outputLen;
  }

  /**
   * Gets output from buffer.
   * If the data in outBuffer fits into buffer byte array, just fill the data and return.
   * If not, a new byte array is created and filled with data in buffer and outBuffer.
   */
  private byte[] getOutput(byte[] buffer, int pos, int bufferLen) {
    int remaining = outBuffer.remaining();
    int outputLen = pos + remaining;
    byte[] output;

    if (outputLen == bufferLen) {
      outBuffer.get(buffer, pos, remaining);
      output = buffer;
    } else {
      output = new byte[outputLen];
      System.arraycopy(buffer, 0, output, 0, pos);
      outBuffer.get(output, pos, remaining);
    }
    return output;
  }

  /**
   * doFinal or update the data in input based on the flag.
   */
  private void updateData(byte[] input, int offset, int len, boolean isFinal)
      throws IllegalBlockSizeException, BadPaddingException, ShortBufferException {
    inBuffer.clear();
    inBuffer.put(input, offset, len);
    inBuffer.flip();

    outBuffer.clear();

    if (isFinal) {
      doFinal(inBuffer, outBuffer);
    } else {
      update(inBuffer, outBuffer);
    }

    outBuffer.flip();
  }
}
