Chimera is a project which strips code related to CryptoInputStream/CryptoOutputStream from Hadoop to facilitate AES-NI based data encryption in other projects.

## Features
  * Fast encryption/decryption
  * JNI-based implementation to achieve comparable performance to the native C++ version based on Openssl
  * Portable across various operating systems (currently only Linux); Chimera loads the library according to your machine environment (It looks system properties, `os.name` and `os.arch`). 
  * Simple usage. Add the chimera-(version).jar file to your classpath.
  * [Apache License Version 2.0](http://www.apache.org/licenses/LICENSE-2.0). Free for both commercial and non-commercial use.

## Download
  * Release version: http://central.maven.org/maven2/com/intel/chimera/chimera/
  * Snapshot version (the latest beta version): https://oss.sonatype.org/content/repositories/snapshots/com/intel/chimera/chimera/

### Using with Maven
  * Chimera is available from Maven's central repository:  <http://central.maven.org/maven2/com/intel/chimera/chimera>

Add the following dependency to your pom.xml:

    <dependency>
      <groupId>com.intel.chimera</groupId>
      <artifactId>chimera</artifactId>
      <version>0.5.0</version>
      <type>jar</type>
      <scope>compile</scope>
    </dependency>

### Using with sbt

```
libraryDependencies += "com.intel.chimera" % "chimera" % "0.5.0"
```

## Usage 

```java
CryptoCodec codec = CryptoCodec.getInstance();
byte[] key = new byte[16];
byte[] iv = new byte[16];
int bufferSize = 4096;
String input = "hello world!";
byte[] decryptedData = new byte[1024];
// Encrypt
ByteArrayOutputStream os = new ByteArrayOutputStream();
CryptoOutputStream cos = new CryptoOutputStream(os, codec, bufferSize, key, iv);
cos.write(input.getBytes("UTF-8"));
cos.flush();
cos.close();

// Decrypt
CryptoInputStream cis = new CryptoInputStream(new ByteArrayInputStream(os.toByteArray()), codec, bufferSize, key, iv);
int decryptedLen = cis.read(decryptedData, 0, 1024);
```

### Configuration
Currently, two crypto codec are supported: JceAesCtrCryptoCodec and OpensslAesCtrCryptoCodec, you can configure which codec to use as follows:

    $ java -Dchimera.crypto.codec.classes.aes.ctr.nopadding=com.intel.chimera.OpensslAesCtrCryptoCodec Sample
    $ java -Dchimera.crypto.codec.classes.aes.ctr.nopadding=com.intel.chimera.JceAesCtrCryptoCodec Sample

## Building from the source code 
Building from the source code is an option when your OS platform and CPU architecture is not supported. To build chimera, you need Git, JDK (1.6 or higher), g++ compiler (mingw in Windows) etc.

    $ git clone https://github.com/intel-hadoop/chimera.git
    $ cd chimera
    $ make

A file `target/chimera-$(version).jar` is the product additionally containing the native library built for your platform.

## For developers

### Make a release
#### Prepare GPG keys
gpg --gen-key                                                 # generate gpg public/private key pair
gpg --list-keys                                               # list available public/private key pairs
gpg --keyserver hkp://pgp.mit.edu --send-keys [public key]    # we use mit pgp server, you can also choose others

#### Configure the credential
Set Sonatype account information (user name and password) in the global sbt settings [$HOME/.sbt/(sbt-version)/sonatype.sbt].
credentials += Credentials("Sonatype Nexus Repository Manager",
        "oss.sonatype.org",
        "(Sonatype user name)",
        "(Sonatype password)")

#### Publish the release
make clean;            # clean up the environment
make publishSigned;    # publish your GPG-signed artifact to staging repository of Sonatype, related files will be uploaded to Sonatype server in this step
make sonatypeRelease;  # make a release. You can also make a release manually in the site of Sonatype [https://oss.sonatype.org].

### Other useful commands
chimera uses sbt (simple build tool for Scala) as a build tool. Here is a simple usage

    $ ./sbt            # enter sbt console
    > ~test            # run tests upon source code change
    > ~test-only *     # run tests that matches a given name pattern  
    > publishM2        # publish jar to $HOME/.m2/repository
    > package          # create jar file
