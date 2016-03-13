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
package com.intel.chimera.conf;

import com.intel.chimera.cipher.JceCipher;

public class ConfigurationKeys {
  public static final String CHIMERA_PREFIX = "chimera.";
  public static final String CHIMERA_SYSTEM_PROPERTIES_FILE =
      CHIMERA_PREFIX + "properties";

	public static final String CONF_PREFIX = "chimera.crypto.";

  // cipher related configuration keys
  public static final String CHIMERA_CRYPTO_CIPHER_CLASSES_KEY =
      CONF_PREFIX + "cipher.classes";
  public static final String CHIMERA_CRYPTO_CIPHER_CLASSES_DEFAULT =
      JceCipher.class.getName();
  public static final String CHIMERA_CRYPTO_CIPHER_JCE_PROVIDER_KEY =
      CONF_PREFIX + "cipher.jce.provider";
  public static final String CHIMERA_CRYPTO_CIPHER_BUFFER_SIZE =
      CONF_PREFIX + "cipher.buffer.size";
  public static final int CHIMERA_CRYPTO_CIPHER_BUFFER_SIZE_DEFAULT = 4 * 1024;

  // security random related configuration keys
  public static final String CHIMERA_CRYPTO_SECURE_RANDOM_DEVICE_FILE_PATH_KEY =
      CONF_PREFIX + "secure.random.device.file.path";
  public static final String CHIMERA_CRYPTO_SECURE_RANDOM_DEVICE_FILE_PATH_DEFAULT =
      "/dev/urandom";
  public static final String CHIMERA_CRYPTO_SECURE_RANDOM_JAVA_ALGORITHM_KEY =
      CONF_PREFIX + "secure.random.java.algorithm";
  public static final String
      CHIMERA_CRYPTO_SECURE_RANDOM_JAVA_ALGORITHM_DEFAULT = "SHA1PRNG";
  public static final String CHIMERA_CRYPTO_SECURE_RANDOM_CLASSES_KEY =
      CONF_PREFIX + "secure.random.classes";

  // stream related configuration keys
  public static final int CHIMERA_CRYPTO_STREAM_BUFFER_SIZE_DEFAULT = 8192;
  public static final String CHIMERA_CRYPTO_STREAM_BUFFER_SIZE_KEY =
      CONF_PREFIX + "stream.buffer.size";

  // native lib related configuration keys
  public static final String CHIMERA_CRYPTO_LIB_PATH_KEY = CONF_PREFIX + "lib" +
      ".path";
  public static final String CHIMERA_CRYPTO_LIB_NAME_KEY = CONF_PREFIX + "lib" +
      ".name";
  public static final String CHIMERA_CRYPTO_LIB_TEMPDIR_KEY = CONF_PREFIX +
      "lib.tempdir";
}
