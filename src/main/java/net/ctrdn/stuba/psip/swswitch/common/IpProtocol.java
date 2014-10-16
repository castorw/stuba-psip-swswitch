package net.ctrdn.stuba.psip.swswitch.common;

import java.util.Arrays;

public enum IpProtocol {

    UNKNOWN("00"),
    TCP("06"),
    UDP("11"),
    ICMP("01");

    private final byte code;
    private byte originalCode;

    private IpProtocol(String code) {
        this.code = DataTypeHelpers.hexStringToByteArray(code)[0];
        this.originalCode = this.code;
    }

    public byte getCode() {
        return code;
    }

    public byte getOriginalCode() {
        return this.originalCode;
    }

    public static IpProtocol valueOf(byte codeByte) {
        for (IpProtocol t : IpProtocol.values()) {
            if (t.getCode() == codeByte) {
                return t;
            }
        }
        IpProtocol proto = IpProtocol.UNKNOWN;
        proto.originalCode = codeByte;
        return proto;
    }
}
