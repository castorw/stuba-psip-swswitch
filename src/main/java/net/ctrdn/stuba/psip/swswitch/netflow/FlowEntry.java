package net.ctrdn.stuba.psip.swswitch.netflow;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Date;
import net.ctrdn.stuba.psip.swswitch.common.EthernetType;
import net.ctrdn.stuba.psip.swswitch.common.IpAddress;
import net.ctrdn.stuba.psip.swswitch.common.IpProtocol;
import net.ctrdn.stuba.psip.swswitch.common.Unsigned;
import net.ctrdn.stuba.psip.swswitch.core.IncomingFrame;
import net.ctrdn.stuba.psip.swswitch.nic.NetworkInterface;

public class FlowEntry {

    private final IpAddress sourceAddress;
    private final IpAddress destinationAddress;
    private final NetworkInterface ingressInterface;
    private final NetworkInterface egressInterface;
    private final IpProtocol ipProtocol;
    private final byte[] sourcePort;
    private final byte[] destinationPort;
    private final Date flowStartDate;

    private Date lastPacketDate;
    private long currentPackets = 0;
    private long currentBytes = 0;
    private byte tcpFlags = 0;

    public FlowEntry(IncomingFrame iframe, NetworkInterface egressInterface) throws UnsupportedPacketException {
        if (!Arrays.equals(EthernetType.IPV4.getCode(), iframe.getPcapPacket().getByteArray(12, 2))) {
            throw new UnsupportedPacketException("Only IPv4 packets are supported by flow exporter.");
        }
        this.sourceAddress = new IpAddress(iframe.getPcapPacket().getByteArray(26, 4));
        this.destinationAddress = new IpAddress(iframe.getPcapPacket().getByteArray(30, 4));
        this.ingressInterface = iframe.getNetworkInterface();
        this.egressInterface = egressInterface;
        this.ipProtocol = IpProtocol.valueOf(iframe.getPcapPacket().getByte(23));
        if (this.ipProtocol == IpProtocol.UNKNOWN) {
            throw new UnsupportedPacketException("This type of IP packet is not supported by flow exporeter (" + this.ipProtocol.toString() + ").");
        }
        if (this.ipProtocol == IpProtocol.TCP || this.ipProtocol == IpProtocol.UDP) {
            this.sourcePort = iframe.getPcapPacket().getByteArray(34, 2);
            this.destinationPort = iframe.getPcapPacket().getByteArray(36, 2);
        } else {
            this.sourcePort = new byte[]{0, 0};
            this.destinationPort = new byte[]{0, 0};
        }
        if (this.ipProtocol == IpProtocol.TCP) {
            this.tcpFlags = iframe.getPcapPacket().getByte(47);
        }
        this.currentPackets = 1;
        this.currentBytes = iframe.getPcapPacket().getCaptureHeader().caplen() - 14;
        this.flowStartDate = new Date();
        this.lastPacketDate = this.flowStartDate;
    }

    public boolean addIfMatches(IncomingFrame iframe) {
        boolean match = this.match(iframe);
        if (match) {
            this.currentPackets++;
            this.currentBytes += iframe.getPcapPacket().getCaptureHeader().caplen() - 14;
            if (this.getIpProtocol() == IpProtocol.TCP) {
                this.tcpFlags |= iframe.getPcapPacket().getByte(47);
            }
            this.lastPacketDate = new Date();
        }
        return match;
    }

    public void resetCounters() {
        this.currentBytes = 0;
        this.currentPackets = 0;
    }

    private boolean match(IncomingFrame iframe) {
        if (Arrays.equals(EthernetType.IPV4.getCode(), iframe.getPcapPacket().getByteArray(12, 2))) {
            if (Arrays.equals(this.getSourceAddress().getAddressBytes(), iframe.getPcapPacket().getByteArray(26, 4)) && Arrays.equals(this.getDestinationAddress().getAddressBytes(), iframe.getPcapPacket().getByteArray(30, 4))) {
                IpProtocol newIpProtocol = IpProtocol.valueOf(iframe.getPcapPacket().getByte(23));
                if (newIpProtocol == IpProtocol.ICMP) {
                    return true;
                } else if (newIpProtocol == IpProtocol.TCP || newIpProtocol == IpProtocol.UDP) {
                    if (Arrays.equals(this.getSourcePort(), iframe.getPcapPacket().getByteArray(34, 2)) && Arrays.equals(this.getDestinationPort(), iframe.getPcapPacket().getByteArray(36, 2))) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    public ByteBuffer toNetflowV5ByteBuffer(FlowExporter flowExporter) {
        ByteBuffer flowRecordBb = ByteBuffer.allocate(48);
        flowRecordBb.put(this.getSourceAddress().getAddressBytes());  // source ip addr
        flowRecordBb.put(this.getDestinationAddress().getAddressBytes()); // destination ip addr
        flowRecordBb.put(new byte[]{0, 0, 0, 0}); // nexthop ip addr
        flowRecordBb.put(flowExporter.getSwitchController().getVirtualNetworkInterfaceSnmpIndex(this.getIngressInterface())); // source iface snmp index
        flowRecordBb.put(flowExporter.getSwitchController().getVirtualNetworkInterfaceSnmpIndex(this.getEgressInterface())); // destination iface snmp index
        Unsigned.putUnsignedInt(flowRecordBb, this.getCurrentPackets()); // packet count
        Unsigned.putUnsignedInt(flowRecordBb, this.getCurrentBytes()); // byte count
        Unsigned.putUnsignedInt(flowRecordBb, this.getFlowStartDate().getTime() - flowExporter.getStartupDate().getTime()); // first packet in flow date timestamp
        Unsigned.putUnsignedInt(flowRecordBb, this.getLastPacketDate().getTime() - flowExporter.getStartupDate().getTime()); // last packet in flow date timestamp
        flowRecordBb.put(this.getSourcePort()); // source l4 port
        flowRecordBb.put(this.getDestinationPort()); // dest l4 port
        flowRecordBb.put((byte) 0); // pad 1
        flowRecordBb.put(this.getTcpFlags()); // cumulated tcp flags
        flowRecordBb.put(this.getIpProtocol().getCode()); // ip proto code
        flowRecordBb.put((byte) 0); // tos
        Unsigned.putUnsignedShort(flowRecordBb, 65535); // source as
        Unsigned.putUnsignedShort(flowRecordBb, 65535); // destination as
        flowRecordBb.put(new byte[]{0, 0}); // pad 2
        return flowRecordBb;
    }

    public IpAddress getSourceAddress() {
        return sourceAddress;
    }

    public IpAddress getDestinationAddress() {
        return destinationAddress;
    }

    public NetworkInterface getIngressInterface() {
        return ingressInterface;
    }

    public NetworkInterface getEgressInterface() {
        return egressInterface;
    }

    public IpProtocol getIpProtocol() {
        return ipProtocol;
    }

    public byte[] getSourcePort() {
        return sourcePort;
    }

    public byte[] getDestinationPort() {
        return destinationPort;
    }

    public Date getFlowStartDate() {
        return flowStartDate;
    }

    public Date getLastPacketDate() {
        return lastPacketDate;
    }

    public long getCurrentPackets() {
        return currentPackets;
    }

    public long getCurrentBytes() {
        return currentBytes;
    }

    public byte getTcpFlags() {
        return tcpFlags;
    }
}
