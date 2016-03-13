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

  private int bufferSize;
  private ByteBuffer inBuffer = null;
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
    return updateOrDoFinal(input, offset, len, true);
  }

  /**
   * Closes the OpenSSL cipher. Clean the Openssl native context.
   */
  @Override
  public void close() {
    cipher.clean();
  }

  private byte[] updateOrDoFinal(byte[] input, int offset, int len, boolean isFinal)
      throws IllegalBlockSizeException, BadPaddingException {
    allocateBuffer();

    int tempLen = isFinal
        ? len - len % transformation.getAlgorithmBlockSize() + transformation.getAlgorithmBlockSize()
        : len - len % transformation.getAlgorithmBlockSize();
    byte[] temp = new byte[tempLen];

    int cursor = consumeInput(input, offset, len, isFinal, temp);
    return generateOutput(temp, cursor, tempLen);
  }

  private void allocateBuffer() {
    if (inBuffer == null) {
      inBuffer = ByteBuffer.allocateDirect(bufferSize);
    }
    if (outBuffer == null) {
      outBuffer = ByteBuffer.allocateDirect(bufferSize + transformation.getAlgorithmBlockSize());
    }
  }

  private int consumeInput(byte[] input, int offset, int len, boolean isFinal, byte[] output)
      throws IllegalBlockSizeException, BadPaddingException {
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

  private byte[] generateOutput(byte[] temp, int cursor, int tempLen) {
    int remaining = outBuffer.remaining();
    int outputLen = cursor + remaining;
    byte[] output;

    if (outputLen == tempLen) {
      outBuffer.get(temp, cursor, remaining);
      output = temp;
    } else {
      output = new byte[outputLen];
      System.arraycopy(temp, 0, output, 0, cursor);
      outBuffer.get(output, cursor, remaining);
    }
    return output;
  }

  private void updateData(byte[] input, int offset, int len, boolean isFinal)
      throws IllegalBlockSizeException, BadPaddingException {
    inBuffer.clear();
    inBuffer.put(input, offset, len);
    inBuffer.flip();

    outBuffer.clear();

    try {
      if (isFinal) {
        doFinal(inBuffer, outBuffer);
      } else {
        update(inBuffer, outBuffer);
      }
    } catch (ShortBufferException e) {
      // this cannot happen.
    }

    outBuffer.flip();
  }
}
