package com.toyberman.fingerprintChange;

import android.os.Build;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.biometric.BiometricPrompt;

import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;

import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.util.Base64;
import android.util.Log;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.content.SharedPreferences;
import android.content.Context;

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
import java.security.SecureRandom;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;

import androidx.biometric.BiometricPrompt;
import androidx.fragment.app.FragmentActivity;

import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

@RequiresApi(api = 29)
public class RNFingerprintChangeModule extends ReactContextBaseJavaModule {

    private final ReactApplicationContext reactContext;
    private final String KEY_NAME = "BIOMETRY_UPDATE_INDICATOR";
    private final String SHARED_PREFERENCES_NAME = "KeyStoreSettings";
    private final String KEYSTORE_IV_NAME = "KeyStoreIV";
    private final String TEST_STRING = "Test string";
    private final String ENCRYPTED_TEST_STRING_KEY = "EncryptedTestStringKey'";
    private final Executor executor = Executors.newSingleThreadExecutor();

    private final byte[] seed = new byte[]{0x01, 0x04, 0x08, 0x07, 0x05, 0x11, 0x14, 0x08, 0x07, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x04, 0x08, 0x07, 0x05, 0x11, 0x14, 0x08, 0x07, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03};

    public RNFingerprintChangeModule(ReactApplicationContext reactContext) {
        super(reactContext);
        this.reactContext = reactContext;
    }

    @ReactMethod
    public void hasFingerPrintChanged(Callback errorCallback, Callback successCallback) throws KeyPermanentlyInvalidatedException, Exception {
        Cipher cipherEncrypt = getCipher();
        Cipher cipherDecrypt = getCipher();

        SecretKey secretKey = getSecretKey();
        Log.i("======F, key at start: ", secretKey == null ? "NULL" : secretKey.toString());
        final SharedPreferences preferences = this.reactContext.getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE);
        if (getSecretKey() == null) {
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
//                byte[] newIv = new byte[16];
//                SecureRandom ivRandom = new SecureRandom();
//                ivRandom.nextBytes(newIv);
//                Log.i("======F, newIv: ", Arrays.toString(newIv));
//                Log.i("======F, newIv.length: ", String.valueOf(newIv.length));
//                String newIvText = Base64.encodeToString(newIv, Base64.DEFAULT);
//                Log.i("======F, newIv Base64: ", newIvText);
//                byte[] iv = new byte[] {0x01, 0x04, 0x08, 0x07, 0x05, 0x11, 0x14, 0x08, 0x07, 0x04, 0x00, 0x00};
//                final IvParameterSpec emptyIvSpec = new IvParameterSpec(iv);
//                SecretKey secretKey2 = new SecretKeySpec(new byte[] {0x01, 0x04, 0x08, 0x07, 0x05, 0x11, 0x13, 0x08, 0x08, 0x04, 0x01, 0x05, 0x06, 0x07, 0x08, 0x03}, "AES");
//                GCMParameterSpec paramsSpec = new GCMParameterSpec(128, newIv);
//                Log.i("======F", "GCMParameterSpec successful");
//                Log.i("======F, cip param: ", cipher.getParameters().toString());
//                Log.i("======F, cip iv: ", Arrays.toString(cipher.getIV()));

            Log.i("======F, test str STORED", preferences.getString(ENCRYPTED_TEST_STRING_KEY, ""));
            if (preferences.getString(ENCRYPTED_TEST_STRING_KEY, "").isEmpty()) {
                cipherEncrypt.init(Cipher.ENCRYPT_MODE, secretKey);
                Log.i("======F", "INIT ENCRYPT successful");
                Log.i("======F, iv ENCRYPT: ", Arrays.toString(cipherEncrypt.getIV()));
                String encodedString = Base64.encodeToString(cipherEncrypt.getIV(), Base64.DEFAULT);
                Log.i("======F, iv ENCR B64: ", encodedString);
                android.content.SharedPreferences.Editor editor = preferences.edit();
                editor.putString(KEYSTORE_IV_NAME, encodedString);
                editor.apply();

                int blockSize = cipherEncrypt.getBlockSize();
                Log.i("======F, C blockSize: ", String.valueOf(blockSize));
            } else {
                Log.i("======F, iv DECR B64: ", preferences.getString(KEYSTORE_IV_NAME, ""));
                byte[] iv = Base64.decode(preferences.getString(KEYSTORE_IV_NAME, ""), Base64.DEFAULT);
                Log.i("======F, iv DECRYPT: ", Arrays.toString(iv));
                GCMParameterSpec spec = new GCMParameterSpec(128, iv);
                cipherDecrypt.init(Cipher.DECRYPT_MODE, secretKey, spec);
                Log.i("======F", "INIT DECRYPT successful");
            }

            BiometricPrompt.CryptoObject crypto;
            if (preferences.getString(ENCRYPTED_TEST_STRING_KEY, "").isEmpty()) {
                crypto = new BiometricPrompt.CryptoObject(cipherEncrypt);
            } else {
                crypto = new BiometricPrompt.CryptoObject(cipherDecrypt);
            }


            final FragmentActivity activity = (FragmentActivity) getCurrentActivity();
            if (null == activity) throw new NullPointerException("Not assigned current activity");

            BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
                    .setTitle("Authorise")
                    .setSubtitle("Please, authorise yourself")
                    .setDescription("This is needed to perform cryptographic operations.")
                    .setNegativeButtonText("Cancel")
                    .build();

            BiometricPrompt.AuthenticationCallback callback = new AuthenticationCallback(successCallback, this.reactContext);

            final BiometricPrompt prompt = new BiometricPrompt(activity, executor, callback);

            prompt.authenticate(promptInfo, crypto);

//                new BiometricPrompt.PromptInfo.Builder()
//                        .setTitle("Authorise")
//                        .setSubtitle("Please, authorise yourself")
//                        .setDescription("This is needed to perform cryptographic operations.")
//                        .setNegativeButtonText("Cancel")
//                        .build()
//                        .authenticate(crypto, new CancellationSignal(), context.getMainExecutor(),
//                                new BiometricCallbackV28(biometricCallback));

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
            successCallback.invoke(true);
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
        return ((SecretKey) keyStore.getKey(KEY_NAME, null));
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

    private class AuthenticationCallback extends BiometricPrompt.AuthenticationCallback {
        private final Callback successCallback;
        private final ReactApplicationContext reactContext;

        private AuthenticationCallback(Callback successCallback, ReactApplicationContext reactContext) {
            this.successCallback = successCallback;
            this.reactContext = reactContext;
        }

        /**
         * Called when an unrecoverable error has been encountered and the operation is complete.
         */
        @Override
        public void onAuthenticationError(final int errorCode, @NonNull final CharSequence errString) {
            Log.i("======F, Error: ", String.valueOf(errString));
            this.successCallback.invoke(true);

        }

        /**
         * Called when a biometric is recognized.
         */
        @Override
        public void onAuthenticationSucceeded(@NonNull final BiometricPrompt.AuthenticationResult result) {
            Log.i("======F, Success", "Success");

            final SharedPreferences preferences = this.reactContext.getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE);
            Cipher cipher = result.getCryptoObject().getCipher();
            Log.i("======F, Success - test str STORED", preferences.getString(ENCRYPTED_TEST_STRING_KEY, ""));
            if (preferences.getString(ENCRYPTED_TEST_STRING_KEY, "").isEmpty()) {
                android.content.SharedPreferences.Editor editor = preferences.edit();
                String testStringToStore = Base64.encodeToString(TEST_STRING.getBytes(), Base64.DEFAULT);
                Log.i("======F, Success - test str to store", testStringToStore);
                try {
                    String encodedResult = Base64.encodeToString(cipher.doFinal(Base64.decode(testStringToStore, Base64.DEFAULT)), Base64.DEFAULT);
                    Log.i("======F, Success - encr str to store", encodedResult);
                    editor.putString(ENCRYPTED_TEST_STRING_KEY, encodedResult);
//                    this.successCallback.invoke(false);
                } catch (Exception e) {
                    Log.i("======F, If Exception: ", e.toString());
                }
                editor.apply();
            } else {
                Log.i("======F, Success", "INSIDE else - decrypt block");
                try {
                    String testStringRecovered = Base64.encodeToString(cipher.doFinal(Base64.decode(preferences.getString(ENCRYPTED_TEST_STRING_KEY, ""), Base64.DEFAULT)), Base64.DEFAULT);
                    Log.i("======F, Success - test str recovered", testStringRecovered);
//                    this.successCallback.invoke(false);
                } catch (Exception e) {
                    Log.i("======F, Else Exception: ", e.toString());
//                    this.successCallback.invoke(true);
                }
            }

        }
    }
}
