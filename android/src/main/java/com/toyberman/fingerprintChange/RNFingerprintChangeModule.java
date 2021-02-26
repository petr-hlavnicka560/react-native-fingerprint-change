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

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import javax.crypto.spec.SecretKeySpec;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Array;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
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
        Log.i("======F, key at start: ", secretKey == null ? "NULL" : secretKey.toString());
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
            Log.i("======F", "key has been created");
            Log.i("======F, key: ", secretKey.toString());
        }
        try {
            Log.i("======F, key in try: ", secretKey.toString());
            byte[] newIv = new byte[16];
            SecureRandom ivRandom = new SecureRandom();
            ivRandom.nextBytes(newIv);
            Log.i("======F, newIv: ", Arrays.toString(newIv));
            Log.i("======F, newIv.length: ", String.valueOf(newIv.length));
            String newIvText = Base64.encodeToString(newIv, Base64.DEFAULT);
            Log.i("======F, newIv Base64: ", newIvText);
//                byte[] iv = new byte[] {0x01, 0x04, 0x08, 0x07, 0x05, 0x11, 0x14, 0x08, 0x07, 0x04, 0x00, 0x00};
//                final IvParameterSpec emptyIvSpec = new IvParameterSpec(iv);
//                SecretKey secretKey2 = new SecretKeySpec(new byte[] {0x01, 0x04, 0x08, 0x07, 0x05, 0x11, 0x13, 0x08, 0x08, 0x04, 0x01, 0x05, 0x06, 0x07, 0x08, 0x03}, "AES");
            GCMParameterSpec paramsSpec = new GCMParameterSpec(128, newIv);
            Log.i("======F", "GCMParameterSpec successful");
//                Log.i("======F, cip param: ", cipher.getParameters().toString());
//                Log.i("======F, cip iv: ", Arrays.toString(cipher.getIV()));
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramsSpec);
            Log.i("======F", "INIT ENCRYPT successful");
            int blockSize = cipher.getBlockSize();
            Log.i("======F, C blockSize: ", String.valueOf(blockSize));
            byte[] testBytes = new byte[blockSize];
            for (int i = 0; i < blockSize; i++) {
                testBytes[i] = 13;
            }
//                for (int i = blockSize; i < 2 * blockSize; i++) {
//                    testBytes[i] = 16;
//                }
//                ByteBuffer inputBuf = ByteBuffer.wrap(testBytes);
//                ByteBuffer outputBuf = ByteBuffer.allocate(1000);;
            Log.i("======F, testBytes: ", Arrays.toString(testBytes));
            Log.i("======F, tB.length: ", String.valueOf(testBytes.length));
            String originalText = Base64.encodeToString(testBytes, Base64.DEFAULT);
            Log.i("======F, tB Base64: ", originalText);
//                String testString = "Test this encryption";
//                byte[] testBytes = adjustTestString(testString).getBytes(StandardCharsets.UTF_8);
//                Log.i("======F, testBytes.length: ", String.valueOf(testBytes.length));

            byte[] cipherBytes = cipher.doFinal(testBytes);
//                int cipherBytes = cipher.doFinal(inputBuf, outputBuf);
//                Log.i("======F, no of bytes in output: ", String.valueOf(cipherBytes));

//                Log.i("======F, cipherBytes: ", Arrays.toString(outputBuf.array()));
//                Log.i("======F, cipherBytes.length: ", String.valueOf(outputBuf.array().length));
//                String cipherString = Base64.encodeToString(outputBuf.array(), Base64.DEFAULT);
//                Log.i("======F, cipherBytes text: ", cipherString);

            Log.i("======F, cipherBytes: ", Arrays.toString(cipherBytes));
            Log.i("======F, cB.length: ", String.valueOf(cipherBytes.length));
            String cipherString = Base64.encodeToString(cipherBytes, Base64.DEFAULT);
            Log.i("======F, cB Base64: ", cipherString);

            Cipher cipher2 = getCipher();
            cipher2.init(Cipher.DECRYPT_MODE, secretKey);
            Log.i("======F", "INIT DECRYPT successful");
            byte[] decryptedBytes = cipher2.doFinal(cipherBytes);
            Log.i("======F, decrBytes: ", Arrays.toString(decryptedBytes));
            Log.i("======F, dB.length: ", String.valueOf(decryptedBytes.length));
            String decryptedText = Base64.encodeToString(decryptedBytes, Base64.DEFAULT);
            Log.i("======F, dB Base64: ", decryptedText);
            successCallback.invoke(false);
        } catch (KeyPermanentlyInvalidatedException e) {
            Log.i("======F", "key has changed");
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
            Log.i("======F, Exception: ", e.toString());
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
                + KeyProperties.BLOCK_MODE_GCM + "/"
                + KeyProperties.ENCRYPTION_PADDING_NONE);
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
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
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
