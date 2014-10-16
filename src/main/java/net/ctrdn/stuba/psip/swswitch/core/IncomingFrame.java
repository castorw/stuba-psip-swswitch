package net.ctrdn.stuba.psip.swswitch.core;

import net.ctrdn.stuba.psip.swswitch.common.MacAddress;
import net.ctrdn.stuba.psip.swswitch.nic.NetworkInterface;
import org.jnetpcap.packet.PcapPacket;

public class IncomingFrame {

    private final NetworkInterface networkInterface;
    private final PcapPacket pcapPacket;

    public IncomingFrame(PcapPacket pcapPacket, NetworkInterface networkInterface) {
        this.pcapPacket = pcapPacket;
        this.networkInterface = networkInterface;
    }

    public PcapPacket getPcapPacket() {
        return pcapPacket;
    }

    public MacAddress getSourceMacAddress() {
        return new MacAddress(this.pcapPacket.getByteArray(6, 6));
    }

    public MacAddress getDestinationMacAddress() {
        return new MacAddress(this.pcapPacket.getByteArray(0, 6));
    }

    public NetworkInterface getNetworkInterface() {
        return networkInterface;
    }
}
