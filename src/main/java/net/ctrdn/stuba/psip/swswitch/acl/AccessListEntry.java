package net.ctrdn.stuba.psip.swswitch.acl;

import net.ctrdn.stuba.psip.swswitch.common.IpProtocol;
import net.ctrdn.stuba.psip.swswitch.common.EthernetType;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import net.ctrdn.stuba.psip.swswitch.common.IpAddress;
import net.ctrdn.stuba.psip.swswitch.common.MacAddress;
import net.ctrdn.stuba.psip.swswitch.common.DataTypeHelpers;
import org.jnetpcap.packet.PcapPacket;

public class AccessListEntry {

    private final int id;
    private final AccessList accessList;
    private int orderKey = 0;
    private MacAddress sourceMacAddress = null;
    private MacAddress destinationMacAddress = null;
    private EthernetType ethernetType = null;
    private IpAddress sourceIpAddress = null;
    private IpAddress destinationIpAddress = null;
    private IpProtocol ipProtocol = null;
    private Integer tcpUdpSourcePort = null;
    private Integer tcpUdpDestinationPort = null;
    private AccessListAction action = AccessListAction.PERMIT;

    private long hitCount = 0;

    public AccessListEntry(AccessList acl, int id) {
        this.id = id;
        this.accessList = acl;
    }

    public MacAddress getSourceMacAddress() {
        return sourceMacAddress;
    }

    public void setSourceMacAddress(MacAddress sourceMacAddress) {
        this.sourceMacAddress = sourceMacAddress;
    }

    public MacAddress getDestinationMacAddress() {
        return destinationMacAddress;
    }

    public void setDestinationMacAddress(MacAddress destinationMacAddress) {
        this.destinationMacAddress = destinationMacAddress;
    }

    public EthernetType getEthernetType() {
        return ethernetType;
    }

    public void setEthernetType(EthernetType ethernetType) {
        this.ethernetType = ethernetType;
    }

    public IpAddress getSourceIpAddress() {
        return sourceIpAddress;
    }

    public void setSourceIpAddress(IpAddress sourceIpAddress) {
        this.sourceIpAddress = sourceIpAddress;
    }

    public IpAddress getDestinationIpAddress() {
        return destinationIpAddress;
    }

    public void setDestinationIpAddress(IpAddress destinationIpAddress) {
        this.destinationIpAddress = destinationIpAddress;
    }

    public IpProtocol getIpProtocol() {
        return ipProtocol;
    }

    public void setIpProtocol(IpProtocol ipProtocol) {
        this.ipProtocol = ipProtocol;
    }

    public Integer getTcpUdpSourcePort() {
        return tcpUdpSourcePort;
    }

    public void setTcpUdpSourcePort(Integer tcpUdpSourcePort) {
        this.tcpUdpSourcePort = tcpUdpSourcePort;
    }

    public Integer getTcpUdpDestinationPort() {
        return tcpUdpDestinationPort;
    }

    public void setTcpUdpDestinationPort(Integer tcpUdpDestinationPort) {
        this.tcpUdpDestinationPort = tcpUdpDestinationPort;
    }

    public AccessListAction getAction() {
        return action;
    }

    public void setAction(AccessListAction action) {
        this.action = action;
    }

    public int getOrderKey() {
        return orderKey;
    }

    public void setOrderKey(int orderKey) {
        this.orderKey = orderKey;
    }

    public AccessListAction evaluate(PcapPacket packet) {
        AccessListAction action = this.evaluateImpl(packet);
        if (action != null) {
            hitCount++;
        }
        return action;
    }

    private AccessListAction evaluateImpl(PcapPacket packet) {
        if (this.sourceMacAddress == null || Arrays.equals(this.sourceMacAddress.getAddressBytes(), packet.getByteArray(6, 6))) {
            if (this.destinationMacAddress == null || Arrays.equals(this.destinationMacAddress.getAddressBytes(), packet.getByteArray(0, 6))) {
                if (this.ethernetType == null || Arrays.equals(this.ethernetType.getCode(), packet.getByteArray(12, 2))) {
                    if (this.ethernetType == EthernetType.ARP) {
                        return this.action;
                    } else if (this.ethernetType == EthernetType.IPV4) {
                        if (this.sourceIpAddress == null || Arrays.equals(this.sourceIpAddress.getAddressBytes(), packet.getByteArray(26, 4))) {
                            if (this.destinationIpAddress == null || Arrays.equals(this.destinationIpAddress.getAddressBytes(), packet.getByteArray(30, 4))) {
                                if (this.ipProtocol == null || this.ipProtocol.getCode() == packet.getByte(23)) {
                                    if (this.ipProtocol == IpProtocol.ICMP) {
                                        return this.action;
                                    } else if (this.ipProtocol == IpProtocol.TCP || this.ipProtocol == IpProtocol.UDP) {
                                        if (this.tcpUdpSourcePort == null || Arrays.equals(this.intTo2Bytes(this.tcpUdpSourcePort), packet.getByteArray(34, 2))) {
                                            if (this.tcpUdpDestinationPort == null || Arrays.equals(this.intTo2Bytes(this.tcpUdpDestinationPort), packet.getByteArray(36, 2))) {
                                                return this.action;
                                            }
                                        }
                                    } else if (this.ipProtocol == null) {
                                        return this.action;
                                    }
                                }
                            }
                        }
                    } else if (this.ethernetType == null) {
                        return this.action;
                    }
                }
            }
        }
        return null;
    }

    private byte[] intTo2Bytes(Integer i) {
        byte[] b = new byte[2];
        b[0] = (byte) ((i & 0xffffffff) >> 8);
        b[1] = (byte) ((i & 0xffffffff));
        return b;
    }

    public Map<String, String> getConfigurationEntries() {
        String aclPrefix = "acl." + DataTypeHelpers.byteArrayToHexString(this.accessList.getId());
        String entryPrefix = aclPrefix + ".entry." + this.getId();
        Map<String, String> config = new HashMap<>();
        config.put(entryPrefix + ".order-key", Integer.toString(this.getOrderKey()));
        config.put(entryPrefix + ".src-mac", this.prepareOptionalParameter(this.sourceMacAddress));
        config.put(entryPrefix + ".dst-mac", this.prepareOptionalParameter(this.destinationMacAddress));
        config.put(entryPrefix + ".ether-type", this.prepareOptionalParameter(this.ethernetType));
        config.put(entryPrefix + ".src-ip", this.prepareOptionalParameter(this.sourceIpAddress));
        config.put(entryPrefix + ".dst-ip", this.prepareOptionalParameter(this.destinationIpAddress));
        config.put(entryPrefix + ".ip-type", this.prepareOptionalParameter(this.ipProtocol));
        config.put(entryPrefix + ".src-port", this.prepareOptionalParameter(this.tcpUdpSourcePort));
        config.put(entryPrefix + ".dst-port", this.prepareOptionalParameter(this.tcpUdpDestinationPort));
        config.put(entryPrefix + ".action", this.prepareOptionalParameter(this.action));
        return config;
    }

    private String prepareOptionalParameter(AccessListAction param) {
        if (param == null) {
            throw new RuntimeException("ACL Entry action can not be null.");
        } else {
            return param.toString();
        }
    }

    private String prepareOptionalParameter(IpProtocol param) {
        if (param == null) {
            return "*";
        } else {
            return param.toString();
        }
    }

    private String prepareOptionalParameter(EthernetType param) {
        if (param == null) {
            return "*";
        } else {
            return param.toString();
        }
    }

    private String prepareOptionalParameter(MacAddress param) {
        if (param == null) {
            return "*";
        } else {
            return param.toString();
        }
    }

    private String prepareOptionalParameter(IpAddress param) {
        if (param == null) {
            return "*";
        } else {
            return param.toString();
        }
    }

    private String prepareOptionalParameter(Integer param) {
        if (param == null) {
            return "*";
        } else {
            return Integer.toString(param);
        }
    }

    public int getId() {
        return id;
    }

    public long getHitCount() {
        return hitCount;
    }

    public void resetHitCount() {
        this.hitCount = 0;
    }
}
