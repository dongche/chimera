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

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.intel.chimera.utils.Utils;

/**
 * Implement the {@link com.intel.chimera.cipher.Cipher} using JCE provider.
 */
public class JceCipher implements Cipher {
  private final Properties props;
  private final CipherTransformation transformation;
  private final javax.crypto.Cipher cipher;

  /**
   * Constructs a {@link com.intel.chimera.cipher.Cipher} based on JCE
   * Cipher {@link javax.crypto.Cipher}.
   * @param props properties for JCE cipher
   * @param transformation transformation for JCE cipher
   * @throws GeneralSecurityException if JCE cipher initialize failed
   */
  public JceCipher(Properties props, CipherTransformation transformation)
      throws GeneralSecurityException {
    this.props = props;
    this.transformation = transformation;

    String provider = Utils.getJCEProvider(props);
    if (provider == null || provider.isEmpty()) {
      cipher = javax.crypto.Cipher.getInstance(transformation.getName());
    } else {
      cipher = javax.crypto.Cipher.getInstance(transformation.getName(), provider);
    }
  }

  @Override
  public CipherTransformation getTransformation() {
    return transformation;
  }

  @Override
  public Properties getProperties() {
    return props;
  }

  @Override
  public CipherType getType() {
    return CipherType.JCE;
  }

  /**
   * Initializes the cipher with mode, key and iv.
   * @param mode {@link #ENCRYPT_MODE} or {@link #DECRYPT_MODE}
   * @param key crypto key for the cipher
   * @param iv Initialization vector for the cipher
   * @throws InvalidAlgorithmParameterException if the given algorithm
   * parameters are inappropriate for this cipher, or this cipher requires
   * algorithm parameters and <code>params</code> is null, or the given
   * algorithm parameters imply a cryptographic strength that would exceed
   * the legal limits (as determined from the configured jurisdiction
   * policy files).
   */
  @Override
  public void init(int mode, byte[] key, byte[] iv)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    Utils.checkNotNull(key);
    Utils.checkNotNull(iv);

    int cipherMode = javax.crypto.Cipher.DECRYPT_MODE;
    if (mode == ENCRYPT_MODE)
      cipherMode = javax.crypto.Cipher.ENCRYPT_MODE;

    cipher.init(cipherMode, new SecretKeySpec(key, "AES"),
        new IvParameterSpec(iv));
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
    return cipher.update(inBuffer, outBuffer);
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
    return cipher.doFinal(inBuffer, outBuffer);
  }

  /**
   * Closes Jce cipher.
   */
  @Override
  public void close() {
    // Do nothing
  }
}
