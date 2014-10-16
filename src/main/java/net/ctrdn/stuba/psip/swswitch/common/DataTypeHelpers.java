package net.ctrdn.stuba.psip.swswitch.common;

import java.text.DecimalFormat;
import java.util.Map;
import javax.xml.xpath.XPath;
import org.w3c.dom.Document;

public class DataTypeHelpers {

    private static Document icmpParamsDocument;
    private static XPath icmpParamsXpath;
    private static Map<Integer, String> udpServiceMap;
    private static Map<Integer, String> tcpServiceMap;

    public static String getReadableByteSize(long size) {
        if (size <= 0) {
            return "0";
        }
        final String[] units = new String[]{"B", "KB", "MB", "GB", "TB", "PB", "EB"};
        int digitGroups = (int) (Math.log10(size) / Math.log10(1024));
        return new DecimalFormat("#,##0.#").format(size / Math.pow(1024, digitGroups)) + " " + units[digitGroups];
    }

    public final static short getUnsignedByteValue(byte b) {
        if (b < 0) {
            return (short) (b & 0xff);
        } else {
            return b;
        }
    }

    public final static int getUnsignedShortValue(short s) {
        if (s < 0) {
            return (s & 0xffff);
        } else {
            return s;
        }
    }

    public final static int getUnsignedShortFromBytes(byte msb, byte lsb) {
        short targetShort = DataTypeHelpers.getUnsignedByteValue(lsb);
        targetShort |= (msb << 8);
        return DataTypeHelpers.getUnsignedShortValue(targetShort);
    }

    public final static String byteArrayToHexString(byte[] a) {
        return DataTypeHelpers.byteArrayToHexString(a, false);
    }

    public final static String byteArrayToHexString(byte[] a, boolean spaces) {
        StringBuilder sb = new StringBuilder(a.length * 2);
        for (byte b : a) {
            sb.append(String.format("%02x", b & 0xff));
            if (spaces) {
                sb.append(" ");
            }
        }
        return sb.toString();
    }

    public final static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}
