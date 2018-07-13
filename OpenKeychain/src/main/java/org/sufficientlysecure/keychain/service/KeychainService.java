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


import android.app.Service;
import android.content.Intent;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Message;
import android.os.Messenger;
import android.os.Parcelable;
import android.os.RemoteException;
import android.support.v4.os.CancellationSignal;

import org.sufficientlysecure.keychain.operations.KeySyncOperation;
import org.sufficientlysecure.keychain.operations.KeySyncParcel;
import org.sufficientlysecure.keychain.KeychainApplication;
import org.sufficientlysecure.keychain.TrackingManager;
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
import org.sufficientlysecure.keychain.daos.KeyWritableRepository;
import org.sufficientlysecure.keychain.service.ServiceProgressHandler.MessageStatus;
import org.sufficientlysecure.keychain.service.input.CryptoInputParcel;
import timber.log.Timber;


/**
 * This Service contains all important long lasting operations for OpenKeychain. It receives Intents with
 * data from the activities or other apps, executes them, and stops itself after doing them.
 */
public class KeychainService extends Service implements Progressable {

    // messenger for communication (hack)
    public static final String EXTRA_MESSENGER = "messenger";

    // extras for operation
    public static final String EXTRA_OPERATION_INPUT = "op_input";
    public static final String EXTRA_CRYPTO_INPUT = "crypto_input";

    public static final String ACTION_CANCEL = "action_cancel";

    // this attribute can possibly merged with the one above? not sure...
    private CancellationSignal mActionCanceled;

    ThreadLocal<Messenger> mMessenger = new ThreadLocal<>();
    private TrackingManager trackingManager;

    @Override
    public void onCreate() {
        super.onCreate();

        trackingManager = ((KeychainApplication) getApplication()).getTrackingManager();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    /**
     * This is run on the main thread, we need to spawn a runnable which runs on another thread for the actual operation
     */
    @Override
    public int onStartCommand(final Intent intent, int flags, int startId) {

        if (intent.getAction() != null && intent.getAction().equals(ACTION_CANCEL)) {
            mActionCanceled.cancel();
            return START_NOT_STICKY;
        }

        mActionCanceled = new CancellationSignal();

        Runnable actionRunnable = new Runnable() {
            @Override
            public void run() {
                Bundle extras = intent.getExtras();

                // Set messenger for communication (for this particular thread)
                mMessenger.set(extras.getParcelable(EXTRA_MESSENGER));

                // Input
                Parcelable inputParcel = extras.getParcelable(EXTRA_OPERATION_INPUT);
                CryptoInputParcel cryptoInput = extras.getParcelable(EXTRA_CRYPTO_INPUT);

                // Operation
                BaseOperation op;

                // just for brevity
                KeychainService outerThis = KeychainService.this;
                KeyWritableRepository databaseInteractor =
                        KeyWritableRepository.create(outerThis);
                if (inputParcel instanceof SignEncryptParcel) {
                    op = new SignEncryptOperation(outerThis, databaseInteractor, outerThis, mActionCanceled);
                } else if (inputParcel instanceof PgpDecryptVerifyInputParcel) {
                    op = new PgpDecryptVerifyOperation(outerThis, databaseInteractor, outerThis);
                } else if (inputParcel instanceof SaveKeyringParcel) {
                    op = new EditKeyOperation(outerThis, databaseInteractor, outerThis, mActionCanceled);
                } else if (inputParcel instanceof  ChangeUnlockParcel) {
                    op = new ChangeUnlockOperation(outerThis, databaseInteractor, outerThis);
                } else if (inputParcel instanceof RevokeKeyringParcel) {
                    op = new RevokeOperation(outerThis, databaseInteractor, outerThis);
                } else if (inputParcel instanceof CertifyActionsParcel) {
                    op = new CertifyOperation(outerThis, databaseInteractor, outerThis, mActionCanceled);
                } else if (inputParcel instanceof DeleteKeyringParcel) {
                    op = new DeleteOperation(outerThis, databaseInteractor, outerThis);
                } else if (inputParcel instanceof PromoteKeyringParcel) {
                    op = new PromoteKeyOperation(outerThis, databaseInteractor, outerThis, mActionCanceled);
                } else if (inputParcel instanceof ImportKeyringParcel) {
                    op = new ImportOperation(outerThis, databaseInteractor, outerThis, mActionCanceled);
                } else if (inputParcel instanceof BackupKeyringParcel) {
                    op = new BackupOperation(outerThis, databaseInteractor, outerThis, mActionCanceled);
                } else if (inputParcel instanceof UploadKeyringParcel) {
                    op = new UploadOperation(outerThis, databaseInteractor, outerThis, mActionCanceled);
                } else if (inputParcel instanceof KeybaseVerificationParcel) {
                    op = new KeybaseVerificationOperation(outerThis, databaseInteractor, outerThis);
                } else if (inputParcel instanceof InputDataParcel) {
                    op = new InputDataOperation(outerThis, databaseInteractor, outerThis);
                } else if (inputParcel instanceof BenchmarkInputParcel) {
                    op = new BenchmarkOperation(outerThis, databaseInteractor, outerThis);
                } else if (inputParcel instanceof KeySyncParcel) {
                    op = new KeySyncOperation(outerThis, databaseInteractor, outerThis, mActionCanceled);
                } else {
                    throw new AssertionError("Unrecognized input parcel in KeychainService!");
                }

                trackingManager.trackInternalServiceCall(op.getClass().getSimpleName());

                @SuppressWarnings("unchecked") // this is unchecked, we make sure it's the correct op above!
                OperationResult result = op.execute(inputParcel, cryptoInput);
                sendMessageToHandler(MessageStatus.OKAY, result);

            }
        };

        Thread actionThread = new Thread(actionRunnable);
        actionThread.start();

        return START_NOT_STICKY;
    }

    private void sendMessageToHandler(MessageStatus status, Integer arg2, Bundle data) {

        Message msg = Message.obtain();
        assert msg != null;
        msg.arg1 = status.ordinal();
        if (arg2 != null) {
            msg.arg2 = arg2;
        }
        if (data != null) {
            msg.setData(data);
        }

        try {
            mMessenger.get().send(msg);
        } catch (RemoteException e) {
            Timber.w(e, "Exception sending message, Is handler present?");
        } catch (NullPointerException e) {
            Timber.w(e, "Messenger is null!");
        }
    }

    private void sendMessageToHandler(MessageStatus status, OperationResult data) {
        Bundle bundle = new Bundle();
        bundle.putParcelable(OperationResult.EXTRA_RESULT, data);
        sendMessageToHandler(status, null, bundle);
    }

    private void sendMessageToHandler(MessageStatus status) {
        sendMessageToHandler(status, null, null);
    }

    /**
     * Set progress of ProgressDialog by sending message to handler on UI thread
     */
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

        sendMessageToHandler(MessageStatus.UPDATE_PROGRESS, null, data);
    }

    @Override
    public void setProgress(int resourceId, int progress, int max) {
        setProgress(getString(resourceId), progress, max);
    }

    @Override
    public void setProgress(int progress, int max) {
        setProgress(null, progress, max);
    }

    @Override
    public void setPreventCancel() {
        sendMessageToHandler(MessageStatus.PREVENT_CANCEL);
    }

}
