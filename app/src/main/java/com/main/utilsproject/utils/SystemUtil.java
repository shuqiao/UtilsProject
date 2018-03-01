package com.main.utilsproject.utils;

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageManager;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.provider.Settings;
import android.support.annotation.RequiresPermission;
import android.support.annotation.WorkerThread;
import android.support.v4.app.ActivityCompat;
import android.telephony.TelephonyManager;
import android.text.TextUtils;
import android.webkit.WebView;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Enumeration;

/**
 * Created by shuqiao on 2018/2/28.
 */

public class SystemUtil {

    private static String UA;

    /**
     * 获取系统浏览器自带的UA，User-agent
     *
     * @param context
     * @return UA
     */
    public static String getUA(Context context) {
        if (TextUtils.isEmpty(UA)) {
            try {
                UA = new WebView(context).getSettings().getUserAgentString();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return UA;
    }

    private static String AAID;

    /**
     * 获取AAID，广告ID
     *
     * @param context
     * @return AAID
     */
    public static String getAAID(Context context) {
        if (AAID == null) {
//            Worker.postWorker(() -> {
//                try {
//                    AAID = AdvertisingIdClient.getAdvertisingIdInfo(context).getId();
//                } catch (Exception e) {
//                    e.printStackTrace();
//                }
//            });
        }
        return AAID;
    }

    /**
     * 获取MCC，移动国家码，三位
     *
     * @param context
     * @return MCC
     */
    public static String getMCC(Context context) {
        String mcc = "";

        try {
            TelephonyManager telManager = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
            if (ActivityCompat.checkSelfPermission(context, Manifest.permission.READ_PHONE_STATE) == PackageManager.PERMISSION_GRANTED) {
                String imsi = telManager.getSubscriberId();
                mcc = imsi.substring(0, 3);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return mcc;
    }

    /**
     * 获取MNC，移动网络码，两位
     *
     * @param context
     * @return MNC
     */
    public static String getMNC(Context context) {
        String mnc = "";

        try {
            TelephonyManager telManager = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
            if (ActivityCompat.checkSelfPermission(context, Manifest.permission.READ_PHONE_STATE) == PackageManager.PERMISSION_GRANTED) {
                String imsi = telManager.getSubscriberId();
                mnc = imsi.substring(3, 5);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return mnc;
    }

    /**
     * 获取IP地址
     *
     * @return MNC
     */
    public static String getLocalIpAddress() {
        try {
            for (Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces();
                 en.hasMoreElements(); ) {
                NetworkInterface networkInterface = en.nextElement();
                for (Enumeration<InetAddress> enumIpAddr = networkInterface.getInetAddresses(); enumIpAddr.hasMoreElements(); ) {
                    InetAddress inetAddress = enumIpAddr.nextElement();
                    if (!inetAddress.isLoopbackAddress() && !inetAddress.isLinkLocalAddress()) {
                        return inetAddress.getHostAddress().toString();
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return "";
    }

    private static String IMEI = "";

    /**
     * 获取IMEI
     *
     * @param context
     * @return IMEI
     */
    @WorkerThread
    @RequiresPermission("android.permission.READ_PHONE_STATE")
    public static String getIMEI(Context context) {
        if (TextUtils.isEmpty(IMEI)) {
            try {
                IMEI = ((TelephonyManager) context.getSystemService("phone")).getDeviceId();
            } catch (Throwable e) {
                IMEI = "";
            }
        }

        return IMEI;
    }

    /**
     * 获取AndroidID
     *
     * @param context
     * @return AndroidID
     */
    public static String getAndroidID(Context context) {
        return Settings.Secure.getString(context.getContentResolver(), "android_id");
    }

    /**
     * 获取MAC地址
     *
     * @param context
     * @return MAC
     */
    public static String getLocalMacAddress(Context context) {
        String mac;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            mac = getMachineHardwareAddress();
        } else {
            WifiManager wifi = (WifiManager) context
                    .getSystemService(Context.WIFI_SERVICE);
            WifiInfo info = wifi.getConnectionInfo();
            mac = info.getMacAddress().replace(":", "");
        }

        return mac;
    }

    /**
     * 获取设备的mac地址和IP地址（android6.0以上专用）
     *
     * @return
     */
    private static String getMachineHardwareAddress() {
        Enumeration<NetworkInterface> interfaces = null;
        try {
            interfaces = NetworkInterface.getNetworkInterfaces();
        } catch (SocketException e) {
            e.printStackTrace();
        }
        String hardWareAddress = null;
        NetworkInterface iF = null;
        while (interfaces.hasMoreElements()) {
            iF = interfaces.nextElement();
            try {
                hardWareAddress = bytesToString(iF.getHardwareAddress());
                if (hardWareAddress == null) continue;
            } catch (SocketException e) {
                e.printStackTrace();
            }
        }
        if (iF != null && iF.getName().equals("wlan0")) {
            hardWareAddress = hardWareAddress.replace(":", "");
        }
        return hardWareAddress;
    }

    /***
     * byte转为String
     * @param bytes
     * @return
     */
    private static String bytesToString(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return null;
        }
        StringBuilder buf = new StringBuilder();
        for (byte b : bytes) {
            buf.append(String.format("%02X:", b));
        }
        if (buf.length() > 0) {
            buf.deleteCharAt(buf.length() - 1);
        }
        return buf.toString();
    }
}
