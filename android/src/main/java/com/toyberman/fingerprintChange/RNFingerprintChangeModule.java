package com.toyberman.fingerprintChange;

import android.os.Build;
import androidx.annotation.RequiresApi;

import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;

import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.util.Log;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Array;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;

@RequiresApi(api = Build.VERSION_CODES.N)
public class RNFingerprintChangeModule extends ReactContextBaseJavaModule{

    private final ReactApplicationContext reactContext;
    private final String KEY_NAME = "BIOMETRY_UPDATE_INDICATOR";

    public RNFingerprintChangeModule(ReactApplicationContext reactContext) {
        super(reactContext);
        this.reactContext = reactContext;
    }

    @ReactMethod
    public void hasFingerPrintChanged(Callback errorCallback, Callback successCallback) throws KeyPermanentlyInvalidatedException, Exception {
        Cipher cipher = getCipher();
        SecretKey secretKey = getSecretKey();
        Log.i("======FINGERPRINT_MODULE, key at start: ", secretKey == null ? "NULL" : secretKey.toString());
        if (getSecretKey() == null){
            generateSecretKey(new KeyGenParameterSpec.Builder(
                    KEY_NAME,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .setUserAuthenticationRequired(true)
                    // Invalidate the keys if the user has registered a new biometric
                    // credential, such as a new fingerprint. Can call this method only
                    // on Android 7.0 (API level 24) or higher. The variable
                    .setInvalidatedByBiometricEnrollment(true)
                    .build());
            secretKey = getSecretKey();
            Log.i("======FINGERPRINT_MODULE", "key has been created");
            Log.i("======FINGERPRINT_MODULE, key: ", secretKey.toString());
        }
        try {
            Log.i("======FINGERPRINT_MODULE, key in try: ", secretKey.toString());
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            Log.i("======FINGERPRINT_MODULE", "INIT ENCRYPT successful");
            Log.i("======FINGERPRINT_MODULE, TEST in bytes: ", Arrays.toString("TEST".getBytes()));
            int blockSize = 8 * cipher.getBlockSize();
            Log.i("======FINGERPRINT_MODULE, blockSize: ", String.valueOf(blockSize));
            byte[] testBytes = new byte[blockSize];
            for (int i = 0; i < blockSize; i++) {
                testBytes[i] = 13;
            }
            Log.i("======FINGERPRINT_MODULE, testBytes: ", Arrays.toString(testBytes));
            Log.i("======FINGERPRINT_MODULE, testBytes.length: ", String.valueOf(testBytes.length));
//                String testString = "Test this encryption";
//                byte[] testBytes = adjustTestString(testString).getBytes(StandardCharsets.UTF_8);
//                Log.i("======FINGERPRINT_MODULE, testBytes.length: ", String.valueOf(testBytes.length));
            byte[] byteCipherText = cipher.doFinal(testBytes);
            Log.i("======FINGERPRINT_MODULE, byteCipherText: ", byteCipherText.toString());
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            Log.i("======FINGERPRINT_MODULE", "INIT DECRYPT successful");
            String plaintext = new String(cipher.doFinal(byteCipherText), "UTF-8");
            Log.i("======FINGERPRINT_MODULE, plaintext decrypted: ", plaintext);
            successCallback.invoke(false);
        } catch (KeyPermanentlyInvalidatedException e) {
            Log.i("======FINGERPRINT_MODULE", "key has changed");
            successCallback.invoke(true);
            generateSecretKey(new KeyGenParameterSpec.Builder(
                    KEY_NAME,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .setUserAuthenticationRequired(true)
                    // Invalidate the keys if the user has registered a new biometric
                    // credential, such as a new fingerprint. Can call this method only
                    // on Android 7.0 (API level 24) or higher. The variable
                    .setInvalidatedByBiometricEnrollment(true)
                    .build());
        } catch (Exception e) {
            Log.i("======FINGERPRINT_MODULE, Exception: ", e.toString());
            e.printStackTrace();
            successCallback.invoke(false);
        }
    }

    private void generateSecretKey(KeyGenParameterSpec keyGenParameterSpec) throws InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        keyGenerator.init(keyGenParameterSpec);
        keyGenerator.generateKey();
    }

    private SecretKey getSecretKey() throws CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableKeyException, KeyStoreException {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");

        // Before the keystore can be accessed, it must be loaded.
        keyStore.load(null);
        return ((SecretKey)keyStore.getKey(KEY_NAME, null));
    }

    private Cipher getCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
        return Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
                + KeyProperties.BLOCK_MODE_CBC + "/"
                + KeyProperties.ENCRYPTION_PADDING_PKCS7);
    }

    private String adjustTestString(String input) throws UnsupportedEncodingException {
        StringBuilder result = new StringBuilder(input);
        while (result.toString().getBytes(StandardCharsets.UTF_8).length % 16 != 0) {
            result.append("\u0020");
        }
        return result.toString();
    }


    @Override
    public String getName() {
        return "RNFingerprintChange";
    }
}
