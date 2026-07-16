package com.beemdevelopment.aegis.importers;

import static java.nio.charset.StandardCharsets.UTF_8;

import android.content.Context;
import android.net.Uri;

import androidx.annotation.NonNull;
import androidx.lifecycle.Lifecycle;

import com.beemdevelopment.aegis.R;
import com.beemdevelopment.aegis.encoding.Base32;
import com.beemdevelopment.aegis.encoding.Base64;
import com.beemdevelopment.aegis.encoding.EncodingException;
import com.beemdevelopment.aegis.helpers.ContextHelper;
import com.beemdevelopment.aegis.otp.GoogleAuthInfo;
import com.beemdevelopment.aegis.otp.GoogleAuthInfoException;
import com.beemdevelopment.aegis.otp.OtpInfoException;
import com.beemdevelopment.aegis.otp.SteamInfo;
import com.beemdevelopment.aegis.ui.dialogs.Dialogs;
import com.beemdevelopment.aegis.ui.tasks.Argon2Task;
import com.beemdevelopment.aegis.util.IOUtils;
import com.beemdevelopment.aegis.util.JsonUtils;
import com.beemdevelopment.aegis.vault.VaultEntry;
import com.google.common.base.Objects;
import com.topjohnwu.superuser.io.SuFile;

import org.bouncycastle.crypto.params.Argon2Parameters;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class ProtonAuthenticatorImporter extends DatabaseImporter {

    public ProtonAuthenticatorImporter(Context context) {
        super(context);
    }

    @Override
    protected SuFile getAppPath() {
        throw new UnsupportedOperationException();
    }

    @Override
    protected @NonNull State read(@NonNull InputStream stream, boolean isInternal) throws DatabaseImporterException {
        try {
            String contents = new String(IOUtils.readAll(stream), UTF_8);
            JSONObject json = new JSONObject(contents);

            if (json.has("salt") && json.has("content")) {
                int version = json.getInt("version");
                if (version != 1) {
                    throw new DatabaseImporterException(String.format("Unsupported version: %d", version));
                }
                byte[] salt = Base64.decode(json.getString("salt"));
                byte[] content = Base64.decode(json.getString("content"));
                return new EncryptedState(salt, content);
            }

            return new DecryptedState(json);
        } catch (JSONException | IOException e) {
            throw new DatabaseImporterException(e);
        }
    }

    public static class EncryptedState extends DatabaseImporter.State {
        private static final int KEY_SIZE = 32;
        private static final int MEMORY_KB = 19 * 1024;
        private static final int ITERATIONS = 2;
        private static final int PARALLELISM = 1;
        private static final int NONCE_SIZE = 12;
        private static final int TAG_SIZE = 16;
        private static final byte[] AAD = "proton.authenticator.export.v1".getBytes(UTF_8);

        private final byte[] _salt;
        private final byte[] _content;

        private EncryptedState(byte[] salt, byte[] content) {
            super(true);
            _salt = salt;
            _content = content;
        }

        public DecryptedState decrypt(char[] password) throws DatabaseImporterException {
            Argon2Task.Params params = getKeyDerivationParams(password);
            SecretKey key = Argon2Task.deriveKey(params);
            return decrypt(key);
        }

        private DecryptedState decrypt(SecretKey key) throws DatabaseImporterException {
            try {
                byte[] nonce = Arrays.copyOfRange(_content, 0, NONCE_SIZE);
                byte[] ct = Arrays.copyOfRange(_content, NONCE_SIZE, _content.length);

                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_SIZE * 8, nonce));
                cipher.updateAAD(AAD);
                byte[] plaintext = cipher.doFinal(ct);

                return new DecryptedState(new JSONObject(new String(plaintext, UTF_8)));
            } catch (BadPaddingException | JSONException e) {
                throw new DatabaseImporterException(e);
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
                     | InvalidAlgorithmParameterException | IllegalBlockSizeException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public void decrypt(Context context, DecryptListener listener) {
            Dialogs.showPasswordInputDialog(context, R.string.enter_password_proton_message, password -> {
                Argon2Task.Params params = getKeyDerivationParams(password);
                Argon2Task task = new Argon2Task(context, key -> {
                    try {
                        DecryptedState state = decrypt(key);
                        listener.onStateDecrypted(state);
                    } catch (DatabaseImporterException e) {
                        listener.onError(e);
                    }
                });
                Lifecycle lifecycle = ContextHelper.getLifecycle(context);
                task.execute(lifecycle, params);
            }, dialog -> listener.onCanceled());
        }

        private Argon2Task.Params getKeyDerivationParams(char[] password) {
            Argon2Parameters argon2Params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                    .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                    .withIterations(ITERATIONS)
                    .withParallelism(PARALLELISM)
                    .withMemoryAsKB(MEMORY_KB)
                    .withSalt(_salt)
                    .build();
            return new Argon2Task.Params(password, argon2Params, KEY_SIZE);
        }
    }

    public static class DecryptedState extends DatabaseImporter.State {
        private final JSONObject _json;

        public DecryptedState(@NonNull JSONObject json) {
            super(false);
            _json = json;
        }

        @Override
        public @NonNull Result convert() throws DatabaseImporterException {
            Result result = new Result();

            try {
                JSONArray entries = _json.getJSONArray("entries");
                for (int i = 0; i < entries.length(); i++) {
                    JSONObject entry = entries.getJSONObject(i);
                    try {
                        result.addEntry(convertEntry(entry));
                    } catch (DatabaseImporterEntryException e) {
                        result.addError(e);
                    }
                }
            } catch (JSONException e) {
                throw new DatabaseImporterException(e);
            }

            return result;
        }

        private static @NonNull VaultEntry convertEntry(@NonNull JSONObject entry) throws DatabaseImporterEntryException {
            try {
                JSONObject content = entry.getJSONObject("content");
                String name = JsonUtils.optString(content, "name");
                if (name == null) {
                    name = "";
                }
                String uriString = content.getString("uri");

                Uri uri = Uri.parse(uriString);
                try {
                    if (Objects.equal(uri.getScheme(), "steam") && uri.getHost() != null) {
                        SteamInfo otp = new SteamInfo(Base32.decode(uri.getHost()));
                        return new VaultEntry(otp, name, "Steam");
                    }

                    GoogleAuthInfo info = GoogleAuthInfo.parseUri(uri);
                    return new VaultEntry(info.getOtpInfo(), name, info.getIssuer());
                } catch (GoogleAuthInfoException | OtpInfoException | EncodingException e) {
                    throw new DatabaseImporterEntryException(e, uriString);
                }
            } catch (JSONException e) {
                throw new DatabaseImporterEntryException(e, entry.toString());
            }
        }
    }
}
