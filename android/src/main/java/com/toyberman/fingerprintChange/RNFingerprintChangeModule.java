package com.toyberman.fingerprintChange;

import android.os.Build;
import androidx.annotation.RequiresApi;

import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;

import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.util.Base64;
import android.util.Log;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import javax.crypto.spec.IvParameterSpec;

import javax.crypto.spec.SecretKeySpec;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Array;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import 	java.security.SecureRandom;
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

    private final byte[] seed = new byte[] {0x01, 0x04, 0x08, 0x07, 0x05, 0x11, 0x14, 0x08, 0x07, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x04, 0x08, 0x07, 0x05, 0x11, 0x14, 0x08, 0x07, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03};

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
//                generateSecretKey(new KeyGenParameterSpec.Builder(
//                        KEY_NAME,
//                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
//                        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
//                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
//                        .setUserAuthenticationRequired(true)
//                        // Invalidate the keys if the user has registered a new biometric
//                        // credential, such as a new fingerprint. Can call this method only
//                        // on Android 7.0 (API level 24) or higher. The variable
//                        .setInvalidatedByBiometricEnrollment(true)
//                        .build());
            generateKey(seed);
            secretKey = getSecretKey();
            Log.i("======FINGERPRINT_MODULE", "key has been created");
            Log.i("======FINGERPRINT_MODULE, key: ", secretKey.toString());
        }
        try {
            Log.i("======FINGERPRINT_MODULE, key in try: ", secretKey.toString());
            final IvParameterSpec emptyIvSpec = new IvParameterSpec(new byte[] {0x01, 0x04, 0x08, 0x07, 0x05, 0x11, 0x14, 0x08, 0x07, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x04, 0x08, 0x07, 0x05, 0x11, 0x14, 0x08, 0x07, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03});
//                SecretKey secretKey2 = new SecretKeySpec(new byte[] {0x01, 0x04, 0x08, 0x07, 0x05, 0x11, 0x13, 0x08, 0x08, 0x04, 0x01, 0x05, 0x06, 0x07, 0x08, 0x03}, "AES");

            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            Log.i("======FINGERPRINT_MODULE", "INIT ENCRYPT successful");
            int blockSize = cipher.getBlockSize();
            Log.i("======FINGERPRINT_MODULE, Cipher blockSize: ", String.valueOf(blockSize));
            byte[] testBytes = new byte[2 * blockSize];
            for (int i = 0; i < blockSize; i++) {
                testBytes[i] = 13;
            }
            for (int i = blockSize; i < 2 * blockSize; i++) {
                testBytes[i] = 16;
            }
            ByteBuffer inputBuf = ByteBuffer.wrap(testBytes);
            ByteBuffer outputBuf = ByteBuffer.allocate(1000);;
            Log.i("======FINGERPRINT_MODULE, testBytes: ", Arrays.toString(testBytes));
            Log.i("======FINGERPRINT_MODULE, testBytes.length: ", String.valueOf(testBytes.length));
            String originalText = Base64.encodeToString(testBytes, Base64.DEFAULT);
            Log.i("======FINGERPRINT_MODULE, testBytes text: ", originalText);
//                String testString = "Test this encryption";
//                byte[] testBytes = adjustTestString(testString).getBytes(StandardCharsets.UTF_8);
//                Log.i("======FINGERPRINT_MODULE, testBytes.length: ", String.valueOf(testBytes.length));

//                byte[] cipherBytes = cipher.doFinal(testBytes);
            int cipherBytes = cipher.doFinal(inputBuf, outputBuf);
            Log.i("======FINGERPRINT_MODULE, no of bytes in output: ", String.valueOf(cipherBytes));

            Log.i("======FINGERPRINT_MODULE, cipherBytes: ", Arrays.toString(outputBuf.array()));
            Log.i("======FINGERPRINT_MODULE, cipherBytes.length: ", String.valueOf(outputBuf.array().length));
            String cipherString = Base64.encodeToString(outputBuf.array(), Base64.DEFAULT);
            Log.i("======FINGERPRINT_MODULE, cipherBytes text: ", cipherString);

//                Log.i("======FINGERPRINT_MODULE, cipherBytes: ", Arrays.toString(cipherBytes));
//                Log.i("======FINGERPRINT_MODULE, cipherBytes.length: ", String.valueOf(cipherBytes.length));
//                String cipherString = Base64.encodeToString(cipherBytes, Base64.DEFAULT);
//                Log.i("======FINGERPRINT_MODULE, cipherBytes text: ", cipherString);

            Cipher cipher2 = getCipher();
            cipher2.init(Cipher.DECRYPT_MODE, secretKey, emptyIvSpec);
            Log.i("======FINGERPRINT_MODULE", "INIT DECRYPT successful");
            byte[] decryptedBytes = cipher2.doFinal(outputBuf.array());
            Log.i("======FINGERPRINT_MODULE, decryptedBytes: ", Arrays.toString(decryptedBytes));
            Log.i("======FINGERPRINT_MODULE, decryptedBytes.length: ", String.valueOf(decryptedBytes.length));
            String decryptedText = Base64.encodeToString(decryptedBytes, Base64.DEFAULT);
            Log.i("======FINGERPRINT_MODULE, plaintext decrypted: ", decryptedText);
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

    private void generateKey(byte[] seed) {
        try {
            SecureRandom random = new SecureRandom();
            random.setSeed(seed);
            KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            keyGenerator.init(new KeyGenParameterSpec.Builder(KEY_NAME, KeyProperties.PURPOSE_ENCRYPT |
                    KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .setUserAuthenticationRequired(true)
                    .setInvalidatedByBiometricEnrollment(true)
//                    .setUnlockedDeviceRequired(true)
//                    .setIsStrongBoxBacked(generateInStrongbox)
                    .setUserAuthenticationValidityDurationSeconds(-1)
                    .setKeySize(256)
                    .build(), random);
            keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException exc) {
            exc.printStackTrace();
        }
    }

    @Override
    public String getName() {
        return "RNFingerprintChange";
    }
}
