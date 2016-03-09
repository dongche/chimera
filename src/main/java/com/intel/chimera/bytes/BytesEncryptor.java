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
package com.intel.chimera.bytes;

import com.intel.chimera.cipher.Cipher;
import com.intel.chimera.cipher.CipherTransformation;
import com.intel.chimera.utils.Utils;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.Properties;

/**
 * An instance of {@link BytesEncryptor} encrypts input bytes and output the ciphertext in the
 * same format. The bytes could be a byte array or a {@link ByteBuffer}.
 */
public class BytesEncryptor extends BytesCipherBase {

  public BytesEncryptor(CipherTransformation transformation, Properties properties, byte[] key,
      byte[] iv) throws IOException {
    this(Utils.getCipherInstance(transformation, properties), key, iv);
  }

  public BytesEncryptor(Cipher cipher, byte[] key, byte[] iv) throws IOException {
    this.cipher = cipher;

    try {
      cipher.init(Cipher.ENCRYPT_MODE, key, iv);
    } catch (InvalidKeyException e) {
      throw new IOException(e);
    } catch(InvalidAlgorithmParameterException e) {
      throw new IOException(e);
    }
  }

  /**
   * Continues a multiple-part encryption operation.
   *
   * @param input the input byte array
   * @param offset the offset in input where the input starts
   * @param len the input length
   * @return the new encrypted byte array. It might be empty depending underlined cipher padding.
   * @throws IOException
   */
  public byte[] update(byte[] input, int offset, int len) throws IOException {
    adaptBuffer(input, offset, len);
    return updateOrDoFinalForByteArray(false);
  }


  /**
   * Encrypts data in a single-part operation, or finishes a multiple-part operation.
   *
   * @param input the input byte array
   * @param offset the offset in input where the input starts
   * @param len the input length
   * @return the new encrypted byte array
   * @throws IOException
   */
  public byte[] doFinal(byte[] input, int offset, int len) throws IOException {
    adaptBuffer(input, offset, len);
    return updateOrDoFinalForByteArray(true);
  }
}
