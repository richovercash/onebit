// SPDX-License-Identifier: AGPL-3.0-only
package onebit.wallet;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;

/**
 * A do-nothing foreground service whose only job is to keep the process
 * "perceptible" for the brief mDL presentation. Android's cached-app freezer only
 * freezes *cached* processes; a running FGS exempts every thread in the process,
 * so {@link MdlSchemeActivity}'s localhost response_uri socket survives while the
 * wallet is foreground. Started before the wallet launch, stopped once we have the bit.
 */
public class KeepAliveService extends Service {
    static final String CH = "onebit-mdl";

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationManager nm = getSystemService(NotificationManager.class);
            nm.createNotificationChannel(new NotificationChannel(CH, "mDL presentation", NotificationManager.IMPORTANCE_LOW));
        }
        Notification n = new Notification.Builder(this, CH)
                .setContentTitle("Verifying mDL")
                .setContentText("Receiving age credential…")
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .build();
        startForeground(1, n);
        return START_NOT_STICKY;
    }

    @Override public IBinder onBind(Intent intent) { return null; }
}