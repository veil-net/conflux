package app.veilnet.conflux

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import anchor.Anchor_
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.os.Build
import androidx.core.app.NotificationCompat
import android.os.ResultReceiver
import android.os.Bundle
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

class VeilNetVPNService : VpnService() {

    companion object {
        const val RESULT_SUCCESS = 1
        const val RESULT_FAILURE = 0
        var anchor: Anchor_? = null
        private var tunInterface: ParcelFileDescriptor? = null
    }
    private var serviceScope: CoroutineScope = CoroutineScope(Dispatchers.IO  + SupervisorJob())

    override fun onDestroy() {
        serviceScope.cancel()
        anchor?.stop()
        tunInterface?.close()
        tunInterface = null
        anchor = null
        super.onDestroy()
    }

    override fun onRevoke() {
        serviceScope.cancel()
        anchor?.stop()
        tunInterface?.close()
        tunInterface = null
        anchor = null
        stopSelf()
        super.onRevoke()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null) return START_NOT_STICKY

        val resultReceiver = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableExtra("result_receiver", ResultReceiver::class.java)
        } else {
            @Suppress("DEPRECATION")
            intent.getParcelableExtra("result_receiver")
        }

        when (intent.action) {
            "Start" -> {
                val guardian = intent.getStringExtra("guardian")
                val token = intent.getStringExtra("token")

                if (guardian == null || token == null) {
                    resultReceiver?.send(RESULT_FAILURE, Bundle().apply {
                        putString("error", "Guardian Url or VeilNet token is missing")
                    })
                    stopSelf()
                    return START_NOT_STICKY
                }

                anchor = Anchor_()
                try {
                    anchor!!.start(guardian, token, "", true, false)
                } catch (e: Exception) {
                    resultReceiver?.send(RESULT_FAILURE, Bundle().apply {
                        putString("error", e.message ?: "Failed to start anchor")
                    })
                    stopSelf()
                    return START_NOT_STICKY
                }

                try {
                    val cidr = anchor!!.cidr
                    val (ip, mask) = cidr.split("/")
                    val gatewayCIDR = anchor!!.gatewayCIDR
                    val (gatewayIP, gatewayMask) = gatewayCIDR.split("/")
                    val builder = Builder()
                        .setSession("VeilNet")
                        .addAddress(ip, mask.toInt())
                        .addDnsServer(gatewayIP)
                        .addRoute("0.0.0.0", 0)
                        .setMtu(1500)
                        .addDisallowedApplication(applicationContext.packageName)
                    tunInterface = builder.establish()
                    serviceScope.launch {
                        anchor!!.attachWithFileDescriptor(tunInterface!!.detachFd().toLong())
                    }
                } catch (e: Exception) {
                    resultReceiver?.send(RESULT_FAILURE, Bundle().apply {
                        putString("error", e.message)
                    })
                    stopSelf()
                    return START_NOT_STICKY
                }

                val notification = buildNotification()
                startForeground(1, notification)

                resultReceiver?.send(RESULT_SUCCESS, null)

                return START_STICKY
            }

            "Stop" -> {
                serviceScope.cancel()
                anchor?.stop()
                tunInterface?.close()
                tunInterface = null
                anchor = null
                stopSelf()
                resultReceiver?.send(RESULT_SUCCESS, null)
                return START_NOT_STICKY
            }

            else -> return START_NOT_STICKY
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val serviceChannel = NotificationChannel(
                "VeilNet",
                "VeilNet", // User-visible name
                NotificationManager.IMPORTANCE_DEFAULT // Or IMPORTANCE_LOW if less intrusive
            ).apply { description = "VeilNet Service Channel" }
            val manager = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(serviceChannel)
        }
    }


    private fun buildNotification(message: String = "VeilNet is active"): Notification {

        createNotificationChannel()

        val notificationIntent = Intent(this, MainActivity::class.java) // Assuming MainActivity is your entry point
        val pendingIntentFlags =
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            notificationIntent,
            pendingIntentFlags
        )

        val builder = NotificationCompat.Builder(this, "VeilNet")
            .setContentTitle("VeilNet")
            .setContentText(message)
            .setSmallIcon(R.drawable.ic_launcher_monochrome)
            .setContentIntent(pendingIntent)
            .setOngoing(true)

        return builder.build()
    }
}