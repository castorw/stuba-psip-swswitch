package net.ctrdn.stuba.psip.swswitch.common;

import java.util.Arrays;

public class MacAddress {

    private final byte[] addressBytes;

    public MacAddress(byte[] address) {
        this.addressBytes = address;
    }

    @Override
    public String toString() {
        String o = "";
        for (int i = 0; i < 6; i++) {
            if (!o.isEmpty()) {
                o += ":";
            }
            String x = Integer.toString(this.getAddressBytes()[i] & 0xff, 16);
            if (x.length() < 2) {
                o += "0";
            }
            o += x;
        }
        return o;
    }

    public static MacAddress fromString(String str) {
        String[] split = str.split(":");
        if (split.length != 6) {
            throw new RuntimeException("invalid mac addr string");
        }
        byte[] bytes = new byte[6];
        for (int i = 0; i < 6; i++) {
            bytes[i] = (byte) (Short.parseShort(split[i], 16) & 0xff);
        }

        return new MacAddress(bytes);
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 59 * hash + Arrays.hashCode(this.getAddressBytes());
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final MacAddress other = (MacAddress) obj;
        if (!Arrays.equals(this.addressBytes, other.addressBytes)) {
            return false;
        }
        return true;
    }

    public byte[] getAddressBytes() {
        return addressBytes;
    }
}
