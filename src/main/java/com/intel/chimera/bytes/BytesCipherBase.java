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
import com.intel.chimera.cipher.CipherType;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Base class for {@link BytesEncryptor} and {@link BytesDecryptor}
 */
public abstract class BytesCipherBase {

  /** the encryption / decryption cipher */
  protected Cipher cipher;

  private ByteBuffer inBuffer = null;
  private ByteBuffer outBuffer = null;


  /**
   * Continues a multiple-part encryption / decryption operation.
   * When using {@link OpensslCipher}, the buffer should be {@link DirectByteBuffer} for
   * performance.
   *
   * @param inBuffer the input byte buffer
   * @param outBuffer the output byte buffer
   * @return number of bytes stored in output
   * @throws IOException
   */
  public int update(ByteBuffer inBuffer, ByteBuffer outBuffer) throws IOException {
    try {
      return cipher.update(inBuffer, outBuffer);
    } catch (ShortBufferException e) {
      throw new IOException(e);
    }
  }

  /**
   * Encrypts / Decrypts data in a single-part operation, or finishes a multiple-part operation.
   * When using {@link OpensslCipher}, the buffer should be {@link DirectByteBuffer} for
   * performance.
   *
   * @param inBuffer the input byte buffer
   * @param outBuffer the output byte buffer
   * @return number of bytes stored in output
   * @throws IOException
   */
  public int doFinal(ByteBuffer inBuffer, ByteBuffer outBuffer) throws IOException {
    try {
      return cipher.doFinal(inBuffer, outBuffer);
    } catch (ShortBufferException e) {
      throw new IOException(e);
    } catch (IllegalBlockSizeException e) {
      throw new IOException(e);
    } catch( BadPaddingException e) {
      throw new IOException(e);
    }
  }

  /**
   * @return the cipher algorithm block size
   */
  public int getCipherBlockSize() {
    return cipher.getTransformation().getAlgorithmBlockSize();
  }

  /**
   * Allocates or reuses the {@link ByteBuffer} and fill input.
   *
   * @param input the input byte array
   * @param offset the offset in input where the input starts
   * @param len the input length
   * @throws IOException
   */
  protected void adaptBuffer(byte[] input, int offset, int len) throws IOException {
    int outputLen = len + getCipherBlockSize();
    if (cipher.getType() == CipherType.JCE) {
      inBuffer = ByteBuffer.wrap(input, offset, len);

      if (outBuffer == null || outBuffer.capacity() < outputLen) {
        outBuffer = ByteBuffer.allocate(outputLen);
      } else {
        outBuffer.clear();
      }
    } else if (cipher.getType() == CipherType.OPENSSL) {
      if (inBuffer == null || inBuffer.capacity() < len) {
        inBuffer = ByteBuffer.allocateDirect(len);
      } else {
        inBuffer.clear();
      }
      inBuffer.put(input, offset, len);
      inBuffer.flip();

      if (outBuffer == null || outBuffer.capacity() < outputLen) {
        outBuffer = ByteBuffer.allocateDirect(outputLen);
      } else {
        outBuffer.clear();
      }
    } else {
      throw new IOException("Unknown cipher type: " + cipher.getType());
    }
  }

  /**
   * Helper method for updating or doFinal byte array.
   *
   * @param isFinal indicates whether update or doFinal
   * @return the encrypted / decrypted byte array
   * @throws IOException
   */
  protected byte[] updateOrDoFinalForByteArray(boolean isFinal) throws IOException {
    if (isFinal) {
      doFinal(inBuffer, outBuffer);
    } else {
      update(inBuffer, outBuffer);
    }

    outBuffer.flip();
    byte[] output = new byte[outBuffer.remaining()];
    outBuffer.get(output);
    return output;
  }
}
