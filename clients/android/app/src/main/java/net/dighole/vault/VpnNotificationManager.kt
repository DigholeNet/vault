// SPDX-License-Identifier: MIT
package net.dighole.vault

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat

/**
 * Manages foreground service notifications for the VPN.
 * Encapsulates notification channel creation, notification building, and updates.
 */
class VpnNotificationManager(private val context: Context) {

    private val notificationManager: NotificationManager =
        context.getSystemService(NotificationManager::class.java)

    fun createNotificationChannel() {
        val channel = NotificationChannel(
            NOTIFICATION_CHANNEL_ID,
            context.getString(R.string.notification_channel_name),
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = context.getString(R.string.notification_channel_description)
        }
        notificationManager.createNotificationChannel(channel)
    }

    fun createNotification(content: String): Notification {
        val pendingIntent = PendingIntent.getActivity(
            context,
            0,
            Intent(context, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(context, NOTIFICATION_CHANNEL_ID)
            .setContentTitle(context.getString(R.string.vpn_service_name))
            .setContentText(content)
            .setSmallIcon(R.drawable.ic_disconnected)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }

    fun updateNotification(content: String) {
        notificationManager.notify(NOTIFICATION_ID, createNotification(content))
    }

    companion object {
        const val NOTIFICATION_CHANNEL_ID = "vault_vpn_channel"
        const val NOTIFICATION_ID = 1001
    }
}
