package net.ctrdn.stuba.psip.swswitch.common;

import java.util.Arrays;

public enum EthernetType {

    UNKNOWN("0000"),
    ARP("0806"),
    IPV4("0800"),
    IPV6("86dd"),
    DOT1Q("8100");

    private final byte[] code;

    private EthernetType(String code) {
        this.code = DataTypeHelpers.hexStringToByteArray(code);
    }

    public byte[] getCode() {
        return code;
    }

    public static EthernetType valueOf(byte[] bytes) {
        for (EthernetType t : EthernetType.values()) {
            if (Arrays.equals(t.getCode(), bytes)) {
                return t;
            }
        }
        return EthernetType.UNKNOWN;
    }
}
