package com.toyberman.fingerprintChange;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Looper;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;
import android.os.Build;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import androidx.biometric.BiometricPrompt;
import androidx.fragment.app.FragmentActivity;

import com.facebook.react.bridge.AssertionException;
import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

@RequiresApi(api = Build.VERSION_CODES.N)
public class RNFingerprintChangeModule extends ReactContextBaseJavaModule {

    private final ReactApplicationContext reactContext;
    private final String KEY_NAME = "BIOMETRY_UPDATE_INDICATOR";
    private final String SHARED_PREFERENCES_NAME = "KeyStoreSettings";
    private final String KEYSTORE_IV_NAME = "KeyStoreIV";
    private final String TEST_STRING = "Test string";
    private final String ENCRYPTED_TEST_STRING_KEY = "EncryptedTestStringKey'";
    private final Executor executor = Executors.newSingleThreadExecutor();

    private final String RESULT_AUTHENTICATION_SUCCESS = "AuthenticationSuccess";
    private final String RESULT_AUTHENTICATION_FAILED = "AuthenticationFailed";
    private final String RESULT_BIOMETRY_CHANGED = "BiometryChanged";
    private final String RESULT_AUTHENTICATION_ERROR = "AuthenticationError";

    private BiometricPrompt.CryptoObject crypto;
    private String result;

    private final byte[] seed = new byte[]{0x01, 0x04, 0x08, 0x07, 0x05, 0x11, 0x14, 0x08, 0x07, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x04, 0x08, 0x07, 0x05, 0x11, 0x14, 0x08, 0x07, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03};

    public RNFingerprintChangeModule(ReactApplicationContext reactContext) {
        super(reactContext);
        this.reactContext = reactContext;
    }

    @ReactMethod
    public void authenticate(Callback errorCallback, Callback successCallback) throws KeyPermanentlyInvalidatedException, Exception {
        Cipher cipherEncrypt = getCipher();
        Cipher cipherDecrypt = getCipher();

        SecretKey secretKey = getSecretKey();
        Log.i("======F, key at start: ", secretKey == null ? "NULL" : secretKey.toString());
        final SharedPreferences preferences = this.reactContext.getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE);
        if (getSecretKey() == null) {
            generateKey(seed);
            secretKey = getSecretKey();
            Log.i("======F", "key has been created");
            Log.i("======F, key: ", secretKey.toString());
        }
        try {
            Log.i("======F, key in try: ", secretKey.toString());

            Log.i("======F, tst str STORED", preferences.getString(ENCRYPTED_TEST_STRING_KEY, ""));
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

            if (preferences.getString(ENCRYPTED_TEST_STRING_KEY, "").isEmpty()) {
                crypto = new BiometricPrompt.CryptoObject(cipherEncrypt);
            } else {
                crypto = new BiometricPrompt.CryptoObject(cipherDecrypt);
            }

            startAuthentication();

            if (this.result.equals(RESULT_AUTHENTICATION_SUCCESS)) {
                successCallback.invoke(RESULT_AUTHENTICATION_SUCCESS);
            } else {
                errorCallback.invoke(this.result);
            }


        } catch (Exception e) {
            Log.i("======F, Exception: ", e.toString());
        }
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

    /**
     * trigger interactive authentication.
     */
    public void startAuthentication() {
        final FragmentActivity activity = (FragmentActivity) getCurrentActivity();
        if (null == activity) throw new NullPointerException("Not assigned current activity");

        // code can be executed only from MAIN thread
        if (Thread.currentThread() != Looper.getMainLooper().getThread()) {
            activity.runOnUiThread(this::startAuthentication);
            waitResult();
            return;
        }

        BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
                .setTitle("Authorise")
                .setSubtitle("Please, authorise yourself")
                .setDescription("This is needed to perform cryptographic operations.")
                .setNegativeButtonText("Cancel")
                .build();

        BiometricPrompt.AuthenticationCallback callback = new AuthenticationCallback(this.reactContext);

        final BiometricPrompt prompt = new BiometricPrompt(activity, executor, callback);

        prompt.authenticate(promptInfo, crypto);
    }

    /**
     * Block current NON-main thread and wait for user authentication results.
     */
    public void waitResult() {
        if (Thread.currentThread() == Looper.getMainLooper().getThread())
            throw new AssertionException("method should not be executed from MAIN thread");

        Log.i("======F", "blocking thread. waiting for done UI operation.");

        try {
            synchronized (this) {
                wait();
            }
        } catch (InterruptedException ignored) {
            /* shutdown sequence */
        }

        Log.i("======F", "unblocking thread.");
    }

    public void onCryptoOperationFinished(@Nullable final String result) {
        this.result = result;

        synchronized (this) {
            notifyAll();
        }
    }

    @Override
    public String getName() {
        return "RNFingerprintChange";
    }

    private class AuthenticationCallback extends BiometricPrompt.AuthenticationCallback {
        private final ReactApplicationContext reactContext;

        private AuthenticationCallback(ReactApplicationContext reactContext) {
            this.reactContext = reactContext;
        }

        /**
         * Called when an unrecoverable error has been encountered and the operation is complete.
         */
        @Override
        public void onAuthenticationError(final int errorCode, @NonNull final CharSequence errString) {
            Log.i("======F, Err code: ", String.valueOf(errorCode));
            Log.i("======F, Error: ", String.valueOf(errString));

            //Error 7  - Too many attempts. Try again later.
            if (errorCode == 7) {
                onCryptoOperationFinished(RESULT_AUTHENTICATION_FAILED);
            } else {
                onCryptoOperationFinished(RESULT_AUTHENTICATION_ERROR);
            }

        }

        /**
         * Called when a biometric is recognized.
         */
        @Override
        public void onAuthenticationSucceeded(@NonNull final BiometricPrompt.AuthenticationResult result) {
            Log.i("======F, Success", "Success");

            final SharedPreferences preferences = this.reactContext.getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE);
            Cipher cipher = result.getCryptoObject().getCipher();
            Log.i("======F, Succ-str STOR", preferences.getString(ENCRYPTED_TEST_STRING_KEY, ""));
            if (preferences.getString(ENCRYPTED_TEST_STRING_KEY, "").isEmpty()) {
                String testStringToStore = Base64.encodeToString(TEST_STRING.getBytes(), Base64.DEFAULT);
                Log.i("======F, Succ-str t str", testStringToStore);
                try {
                    String encodedResult = Base64.encodeToString(cipher.doFinal(Base64.decode(testStringToStore, Base64.DEFAULT)), Base64.DEFAULT);
                    Log.i("======F, Succ-encr str", encodedResult);
                    android.content.SharedPreferences.Editor editor = preferences.edit();
                    editor.putString(ENCRYPTED_TEST_STRING_KEY, encodedResult);
                    editor.apply();
                    onCryptoOperationFinished(RESULT_AUTHENTICATION_SUCCESS);
                } catch (Exception e) {
                    Log.i("======F, If Exception: ", e.toString());
                    onCryptoOperationFinished(RESULT_AUTHENTICATION_ERROR);
                }
            } else {
                Log.i("======F, Success", "INSIDE else - decrypt block");
                try {
                    String testStringRecovered = Base64.encodeToString(cipher.doFinal(Base64.decode(preferences.getString(ENCRYPTED_TEST_STRING_KEY, ""), Base64.DEFAULT)), Base64.DEFAULT);
                    Log.i("======F, Succ-s rec", testStringRecovered);
                    onCryptoOperationFinished(RESULT_AUTHENTICATION_SUCCESS);
                } catch (IllegalBlockSizeException illegalBlockSizeException) {
                    Log.i("======F, Else Exc: ", illegalBlockSizeException.toString());
                    onCryptoOperationFinished(RESULT_BIOMETRY_CHANGED);
                } catch (Exception e) {
                    Log.i("======F, If Exception: ", e.toString());
                    onCryptoOperationFinished(RESULT_AUTHENTICATION_ERROR);
                }
            }

        }
    }
}
