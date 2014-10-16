package net.ctrdn.stuba.psip.swswitch.common;

import java.util.Arrays;

public class IpAddress {

    private final byte[] addressBytes;

    public IpAddress(byte[] address) {
        this.addressBytes = address;
    }

    @Override
    public String toString() {
        return (getAddressBytes()[0] & 0xff) + "." + (getAddressBytes()[1] & 0xff) + "." + (getAddressBytes()[2] & 0xff) + "." + (getAddressBytes()[3] & 0xff);
    }

    public static IpAddress fromString(String str) {
        String[] split = str.split("\\.");
        if (split.length != 4) {
            throw new RuntimeException("invalid ip addr string");
        }
        byte[] bytes = new byte[4];
        for (int i = 0; i < 4; i++) {
            bytes[i] = (byte) (Short.parseShort(split[i]) & 0xff);
        }
        return new IpAddress(bytes);
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
        final IpAddress other = (IpAddress) obj;
        if (!Arrays.equals(this.addressBytes, other.addressBytes)) {
            return false;
        }
        return true;
    }

    public byte[] getAddressBytes() {
        return addressBytes;
    }
}
