# Cryptography

## Asymmetric Algorithm `RSA`
```java
import android.util.Base64;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import javax.crypto.Cipher;

// plain text
String plainText = "This is just a simple test!";

// Generate key pair for 1024-bit RSA encryption and decryption
Key publicKey = null;
Key privateKey = null;
try {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(1024);
    KeyPair kp = kpg.genKeyPair();
    publicKey = kp.getPublic();
    privateKey = kp.getPrivate();		
} catch (Exception e) {
    e.printStackTrace();
}

// Encode the plain data with RSA private key
byte[] encodedBytes = null;
try {
    Cipher c = Cipher.getInstance("RSA");
    c.init(Cipher.ENCRYPT_MODE, privateKey);
    encodedBytes = c.doFinal(plainText.getBytes());
} catch (Exception e) {
    e.printStackTrace();
}		
String cipherText = Base64.encodeToString(encodedBytes, Base64.DEFAULT);

// Decode the encoded data with RSA public key
byte[] decodedBytes = null;
try {
    Cipher c = Cipher.getInstance("RSA");
    c.init(Cipher.DECRYPT_MODE, publicKey);
    decodedBytes = c.doFinal(encodedBytes);
} catch (Exception e) {
    e.printStackTrace();
}		
String decodeText = new String(decodedBytes);
```

## Symmetric Algorithm `AES`
```java
import android.util.Base64;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;

// plain text
String plainText = "This is just a simple test!";

// Set up secret key spec for 128-bit AES encryption and decryption
SecretKeySpec sks = null;
try {
    SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
    sr.setSeed("any data used as random seed".getBytes());
    KeyGenerator kg = KeyGenerator.getInstance("AES");
    kg.init(128, sr);
    sks = new SecretKeySpec((kg.generateKey()).getEncoded(), "AES");
} catch (Exception e) {
    e.printStackTrace();
}

// Encode the plain data with AES
byte[] encodedBytes = null;
try {
    Cipher c = Cipher.getInstance("AES");
    c.init(Cipher.ENCRYPT_MODE, sks);
    encodedBytes = c.doFinal(plainText.getBytes());
} catch (Exception e) {
    e.printStackTrace();
}	
String cipherText = Base64.encodeToString(encodedBytes, Base64.DEFAULT);

// Decode the encoded data with AES
byte[] decodedBytes = null;
try {
    Cipher c = Cipher.getInstance("AES");
    c.init(Cipher.DECRYPT_MODE, sks);
    decodedBytes = c.doFinal(encodedBytes);
} catch (Exception e) {
    e.printStackTrace();
}		
String decodeText = new String(decodedBytes);	
```

## Crypto Algorithms
```java
import java.security.Provider;
import java.security.Security;
import java.util.Iterator;
import java.util.Set;
import java.util.TreeSet;

String result = "";

// Get all the providers
Provider[] providers = Security.getProviders();

for (int p = 0; p < providers.length; p++) {
    // Get all service types for a specific provider
    Set<Object> ks = providers[p].keySet();
    Set<String> servicetypes = new TreeSet<String>();
    for (Iterator<Object> it = ks.iterator(); it.hasNext();) {
        String k = it.next().toString();
        k = k.split(" ")[0];
        if (k.startsWith("Alg.Alias."))
            k = k.substring(10);				
        
        servicetypes.add(k.substring(0, k.indexOf('.')));
    }
    
    // Get all algorithms for a specific service type
    int s = 1;
    for (Iterator<String> its = servicetypes.iterator(); its.hasNext();) {
        String stype = its.next();
        Set<String> algorithms = new TreeSet<String>();
        for (Iterator<Object> it = ks.iterator(); it.hasNext();) {
            String k = it.next().toString();
            k = k.split(" ")[0];
            if (k.startsWith(stype + "."))
                algorithms.add(k.substring(stype.length() + 1));
            else if (k.startsWith("Alg.Alias." + stype +".")) 
                algorithms.add(k.substring(stype.length() + 11));
        }

        int a = 1;
        for (Iterator<String> ita = algorithms.iterator(); ita.hasNext();) {
            result += ("[P#" + (p + 1) + ":" + providers[p].getName() + "]" +
                    "[S#" + s + ":" + stype + "]" +
                    "[A#" + a + ":" + ita.next() + "]\n");
            a++;
        }
        
        s++;
    }
}
```

## Credit
```
cliu.tutorialoncrypto
```