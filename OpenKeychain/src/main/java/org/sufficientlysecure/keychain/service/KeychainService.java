/*
 * Copyright (C) 2017 Schürmann & Breitmoser GbR
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.sufficientlysecure.keychain.service;


import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import android.content.Context;
import android.os.Bundle;
import android.os.Message;
import android.os.Messenger;
import android.os.Parcelable;
import android.os.RemoteException;

import org.sufficientlysecure.keychain.operations.BackupOperation;
import org.sufficientlysecure.keychain.operations.BaseOperation;
import org.sufficientlysecure.keychain.operations.BenchmarkOperation;
import org.sufficientlysecure.keychain.operations.CertifyOperation;
import org.sufficientlysecure.keychain.operations.ChangeUnlockOperation;
import org.sufficientlysecure.keychain.operations.DeleteOperation;
import org.sufficientlysecure.keychain.operations.EditKeyOperation;
import org.sufficientlysecure.keychain.operations.ImportOperation;
import org.sufficientlysecure.keychain.operations.InputDataOperation;
import org.sufficientlysecure.keychain.operations.KeybaseVerificationOperation;
import org.sufficientlysecure.keychain.operations.PromoteKeyOperation;
import org.sufficientlysecure.keychain.operations.RevokeOperation;
import org.sufficientlysecure.keychain.operations.SignEncryptOperation;
import org.sufficientlysecure.keychain.operations.UploadOperation;
import org.sufficientlysecure.keychain.operations.results.OperationResult;
import org.sufficientlysecure.keychain.pgp.PgpDecryptVerifyInputParcel;
import org.sufficientlysecure.keychain.pgp.PgpDecryptVerifyOperation;
import org.sufficientlysecure.keychain.pgp.Progressable;
import org.sufficientlysecure.keychain.pgp.SignEncryptParcel;
import org.sufficientlysecure.keychain.provider.KeyWritableRepository;
import org.sufficientlysecure.keychain.service.ServiceProgressHandler.MessageStatus;
import org.sufficientlysecure.keychain.service.input.CryptoInputParcel;
import timber.log.Timber;


public class KeychainService {
    private static KeychainService keychainService;

    public static KeychainService getInstance(Context context) {
        if (keychainService == null) {
            keychainService = new KeychainService(context.getApplicationContext());
        }
        return keychainService;
    }

    private KeychainService(Context context) {
        this.context = context;
        this.threadPoolExecutor = new ThreadPoolExecutor(0, 4, 1000, TimeUnit.MILLISECONDS, new LinkedBlockingQueue<>());
        this.keyRepository = KeyWritableRepository.create(context);
    }

    private final Context context;
    private final ThreadPoolExecutor threadPoolExecutor;
    private final KeyWritableRepository keyRepository;

    // this attribute can possibly merged with the one above? not sure...
    private AtomicBoolean mActionCanceled = new AtomicBoolean(false);

    public void startOperationInBackground(Parcelable inputParcel, CryptoInputParcel cryptoInput, Messenger messenger) {
        mActionCanceled.set(false);

        Communicator communicator = new Communicator(messenger);

        Progressable progressable = new Progressable() {
            @Override
            public void setProgress(String message, int progress, int max) {
                Timber.d("Send message by setProgress with progress=" + progress + ", max="
                        + max);

                Bundle data = new Bundle();
                if (message != null) {
                    data.putString(ServiceProgressHandler.DATA_MESSAGE, message);
                }
                data.putInt(ServiceProgressHandler.DATA_PROGRESS, progress);
                data.putInt(ServiceProgressHandler.DATA_PROGRESS_MAX, max);

                communicator.sendMessageToHandler(MessageStatus.UPDATE_PROGRESS, data);
            }

            @Override
            public void setProgress(int resourceId, int progress, int max) {
                setProgress(context.getString(resourceId), progress, max);
            }

            @Override
            public void setProgress(int progress, int max) {
                setProgress(null, progress, max);
            }

            @Override
            public void setPreventCancel() {
                communicator.sendMessageToHandler(MessageStatus.PREVENT_CANCEL, (Bundle) null);
            }
        };

        Runnable actionRunnable = () -> {
            BaseOperation op;

            if (inputParcel instanceof SignEncryptParcel) {
                op = new SignEncryptOperation(context, keyRepository, progressable, mActionCanceled);
            } else if (inputParcel instanceof PgpDecryptVerifyInputParcel) {
                op = new PgpDecryptVerifyOperation(context, keyRepository, progressable);
            } else if (inputParcel instanceof SaveKeyringParcel) {
                op = new EditKeyOperation(context, keyRepository, progressable, mActionCanceled);
            } else if (inputParcel instanceof  ChangeUnlockParcel) {
                op = new ChangeUnlockOperation(context, keyRepository, progressable);
            } else if (inputParcel instanceof RevokeKeyringParcel) {
                op = new RevokeOperation(context, keyRepository, progressable);
            } else if (inputParcel instanceof CertifyActionsParcel) {
                op = new CertifyOperation(context, keyRepository, progressable, mActionCanceled);
            } else if (inputParcel instanceof DeleteKeyringParcel) {
                op = new DeleteOperation(context, keyRepository, progressable);
            } else if (inputParcel instanceof PromoteKeyringParcel) {
                op = new PromoteKeyOperation(context, keyRepository, progressable, mActionCanceled);
            } else if (inputParcel instanceof ImportKeyringParcel) {
                op = new ImportOperation(context, keyRepository, progressable, mActionCanceled);
            } else if (inputParcel instanceof BackupKeyringParcel) {
                op = new BackupOperation(context, keyRepository, progressable, mActionCanceled);
            } else if (inputParcel instanceof UploadKeyringParcel) {
                op = new UploadOperation(context, keyRepository, progressable, mActionCanceled);
            } else if (inputParcel instanceof KeybaseVerificationParcel) {
                op = new KeybaseVerificationOperation(context, keyRepository, progressable);
            } else if (inputParcel instanceof InputDataParcel) {
                op = new InputDataOperation(context, keyRepository, progressable);
            } else if (inputParcel instanceof BenchmarkInputParcel) {
                op = new BenchmarkOperation(context, keyRepository, progressable);
            } else {
                throw new AssertionError("Unrecognized input parcel in KeychainService!");
            }

            @SuppressWarnings("unchecked") // this is unchecked, we make sure it's the correct op above!
            OperationResult result = op.execute(inputParcel, cryptoInput);
            communicator.sendMessageToHandler(MessageStatus.OKAY, result);
        };

        threadPoolExecutor.execute(actionRunnable);
    }

    public void cancelRunningTask() {
        if (mActionCanceled != null) {
            mActionCanceled.set(true);
        }
    }

    public static class Communicator {
        final Messenger messenger;

        Communicator(Messenger messenger) {
            this.messenger = messenger;
        }

        void sendMessageToHandler(MessageStatus status, Bundle data) {
            Message msg = Message.obtain();
            assert msg != null;
            msg.arg1 = status.ordinal();
            if (data != null) {
                msg.setData(data);
            }

            try {
                messenger.send(msg);
            } catch (RemoteException e) {
                Timber.w(e, "Exception sending message, Is handler present?");
            } catch (NullPointerException e) {
                Timber.w(e, "Messenger is null!");
            }
        }

        void sendMessageToHandler(MessageStatus status, OperationResult data) {
            Bundle bundle = new Bundle();
            bundle.putParcelable(OperationResult.EXTRA_RESULT, data);
            sendMessageToHandler(status, bundle);
        }
    }

}
