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
 * An instance of {@link BytesDecryptor} decrypts input bytes and output the plaintext in the
 * same format. The bytes could be a byte array or a {@link ByteBuffer}.
 */
public class BytesDecryptor extends BytesCipherBase {

  public BytesDecryptor(CipherTransformation transformation, Properties properties, byte[] key,
      byte[] iv) throws IOException {
    this(Utils.getCipherInstance(transformation, properties), key, iv);
  }

  public BytesDecryptor(Cipher cipher, byte[] key, byte[] iv) throws IOException {
    this.cipher = cipher;

    try {
      cipher.init(Cipher.DECRYPT_MODE, key, iv);
    } catch (InvalidKeyException e) {
      throw new IOException(e);
    } catch(InvalidAlgorithmParameterException e) {
      throw new IOException(e);
    }
  }

  /**
   * Continues a multiple-part decryption operation.
   *
   * @param input the input byte array
   * @param offset the offset in input where the input starts
   * @param len the input length
   * @return the new decrypted byte array. It might be empty depending underlined cipher padding.
   * @throws IOException
   */
  public byte[] update(byte[] input, int offset, int len) throws IOException {
    adaptBuffer(input, offset, len, len);
    return updateOrDoFinalForByteArray(false);
  }

  /**
   * Decrypts data in a single-part operation, or finishes a multiple-part operation.
   *
   * @param input the input byte array
   * @param offset the offset in input where the input starts
   * @param len the input length
   * @return the new decrypted byte array
   * @throws IOException
   */
  public byte[] doFinal(byte[] input, int offset, int len) throws IOException {
    adaptBuffer(input, offset, len, len);
    return updateOrDoFinalForByteArray(true);
  }
}
