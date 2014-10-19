package net.ctrdn.stuba.psip.swswitch.nic;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import net.ctrdn.stuba.psip.swswitch.core.IncomingFrame;
import net.ctrdn.stuba.psip.swswitch.common.MacAddress;
import net.ctrdn.stuba.psip.swswitch.core.MacTableEntry;
import net.ctrdn.stuba.psip.swswitch.core.SwitchController;
import net.ctrdn.stuba.psip.swswitch.acl.AccessList;
import net.ctrdn.stuba.psip.swswitch.common.DataTypeHelpers;
import net.ctrdn.stuba.psip.swswitch.common.EthernetType;
import net.ctrdn.stuba.psip.swswitch.common.IpProtocol;
import net.ctrdn.stuba.psip.swswitch.common.Unsigned;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class NetworkInterface {

    private final Logger logger = LoggerFactory.getLogger(NetworkInterface.class);
    private AccessList ingressAccessList = null;
    private AccessList egressAccessList = null;
    private boolean active = false;

    public boolean isActive() {
        return active;
    }

    public AccessList getIngressAccessList() {
        return ingressAccessList;
    }

    public void setIngressAccessList(AccessList ingressAccessList) {
        this.ingressAccessList = ingressAccessList;
        if (ingressAccessList != null) {
            this.logger.info("Attached access list " + DataTypeHelpers.byteArrayToHexString(ingressAccessList.getId()) + " for ingress traffic on interface " + this.getPcapInterface().getName());
        } else {
            this.logger.info("Detached access list for ingress traffic on interface " + this.getPcapInterface().getName());
        }
    }

    public AccessList getEgressAccessList() {
        return egressAccessList;
    }

    public void setEgressAccessList(AccessList egressAccessList) {
        this.egressAccessList = egressAccessList;
        if (egressAccessList != null) {
            this.logger.info("Attached access list " + DataTypeHelpers.byteArrayToHexString(egressAccessList.getId()) + " for egress traffic on interface " + this.getPcapInterface().getName());
        } else {
            this.logger.info("Detached access list for egress traffic on interface " + this.getPcapInterface().getName());
        }
    }

    private class Receiver implements Runnable {

        private final NetworkInterface networkInterface = NetworkInterface.this;
        private final Logger logger = NetworkInterface.this.logger;
        private boolean running = true;

        @Override
        public void run() {
            PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

                @Override
                public void nextPacket(PcapPacket packet, String user) {
                    IncomingFrame iframe = new IncomingFrame(packet, Receiver.this.networkInterface);
                    Receiver.this.logger.debug("Received frame from " + Receiver.this.networkInterface.pcapInterface.getName() + "; srcmac: " + iframe.getSourceMacAddress().toString() + ", dstmac: " + iframe.getDestinationMacAddress());
                    Receiver.this.networkInterface.switchController.offerIncomingFrame(iframe);
                    Receiver.this.networkInterface.stats.rxPackets += 1;
                    Receiver.this.networkInterface.stats.rxBytes += iframe.getPcapPacket().getCaptureHeader().caplen();

                    EthernetType ethernetType = EthernetType.valueOf(packet.getByteArray(12, 2));
                    Receiver.this.networkInterface.stats.addEthernetType(ethernetType, iframe.getPcapPacket().getCaptureHeader().caplen());

                    if (ethernetType == EthernetType.IPV4) {
                        IpProtocol ipProtocol = IpProtocol.valueOf(packet.getByte(23));
                        Receiver.this.networkInterface.stats.addIpProtocol(ipProtocol, iframe.getPcapPacket().getCaptureHeader().caplen());

                        if (ipProtocol == IpProtocol.TCP || ipProtocol == IpProtocol.UDP) {
                            int sourcePort = Unsigned.getUnsignedShort(ByteBuffer.wrap(packet.getByteArray(34, 2)));
                            int destinationPort = Unsigned.getUnsignedShort(ByteBuffer.wrap(packet.getByteArray(36, 2)));
                            Receiver.this.networkInterface.stats.addSourceVirtualPortStatsEntry(sourcePort, iframe.getPcapPacket().getCaptureHeader().caplen());
                            Receiver.this.networkInterface.stats.addDestinationVirtualPortStatsEntry(destinationPort, iframe.getPcapPacket().getCaptureHeader().caplen());
                        }
                    }
                }
            };

            while (this.running) {
                this.networkInterface.pcap.loop(Pcap.LOOP_INFINITE, jpacketHandler, null);
            }
        }

        public void stop() {
            this.running = false;
            this.networkInterface.pcap.breakloop();
        }

    }

    private class RealtimeStats implements Runnable, NicRealtimeStats {

        private final NetworkInterface networkInterface = NetworkInterface.this;
        private final Logger logger = NetworkInterface.this.logger;
        private boolean running = true;
        private final int sleepTime = 2000;
        private long lastTxPackets = 0;
        private long lastTxBytes = 0;
        private long lastRxPackets = 0;
        private long lastRxBytes = 0;
        private long txThroughputPackets;
        private long txThroughputBytes;
        private long rxThroughputPackets;
        private long rxThroughputBytes;

        @Override
        public void run() {
            try {
                while (this.running) {
                    this.txThroughputPackets = (this.networkInterface.stats.txPackets - this.lastTxPackets) / (this.sleepTime / 1000);
                    this.txThroughputBytes = (this.networkInterface.stats.txBytes - this.lastTxBytes) / (this.sleepTime / 1000);
                    this.rxThroughputPackets = (this.networkInterface.stats.rxPackets - this.lastRxPackets) / (this.sleepTime / 1000);
                    this.rxThroughputBytes = (this.networkInterface.stats.rxBytes - this.lastRxBytes) / (this.sleepTime / 1000);
                    this.lastTxPackets = this.networkInterface.stats.txPackets;
                    this.lastTxBytes = this.networkInterface.stats.txBytes;
                    this.lastRxPackets = this.networkInterface.stats.rxPackets;
                    this.lastRxBytes = this.networkInterface.stats.rxBytes;
                    Thread.sleep(this.sleepTime);
                }
            } catch (InterruptedException ex) {
                this.logger.error("Interrupted", ex);
            }
        }

        public void stop() {
            this.running = false;
        }

        @Override
        public long getTxThroughputPackets() {
            return txThroughputPackets;
        }

        @Override
        public long getTxThroughputBytes() {
            return txThroughputBytes;
        }

        @Override
        public long getRxThroughputPackets() {
            return rxThroughputPackets;
        }

        @Override
        public long getRxThroughputBytes() {
            return rxThroughputBytes;
        }

        @Override
        public void reset() {
            this.lastRxBytes = 0;
            this.lastTxBytes = 0;
            this.lastRxPackets = 0;
            this.lastTxPackets = 0;
        }
    }

    private class NicStatsImpl implements NicStats {

        private long rxBytes = 0;
        private long rxPackets = 0;
        private long txBytes = 0;
        private long txPackets = 0;
        private final List<EthernetTypeStatsEntry> ethernetTypeStatsList = new ArrayList<>();
        private final List<IpProtocolStatsEntry> ipProtocolStatsList = new ArrayList<>();
        private final List<VirtualPortStatsEntry> sourceVirtualPortStatsList = new ArrayList<>();
        private final List<VirtualPortStatsEntry> destinationVirtualPortStatsList = new ArrayList<>();

        @Override
        public long getRxPackets() {
            return this.rxPackets;
        }

        @Override
        public long getRxBytes() {
            return this.rxBytes;
        }

        @Override
        public long getTxPackets() {
            return this.txPackets;
        }

        @Override
        public long getTxBytes() {
            return this.txBytes;
        }

        @Override
        public NicRealtimeStats getRealtimeStats() {
            return NetworkInterface.this.realtimeStats;
        }

        @Override
        public void reset() {
            this.rxBytes = 0;
            this.rxPackets = 0;
            this.txBytes = 0;
            this.txPackets = 0;
            this.ethernetTypeStatsList.clear();
            this.ipProtocolStatsList.clear();
            this.sourceVirtualPortStatsList.clear();
            this.destinationVirtualPortStatsList.clear();
            this.getRealtimeStats().reset();
        }

        @Override
        public List<EthernetTypeStatsEntry> getRxEthernetTypeStats() {
            return this.ethernetTypeStatsList;
        }

        @Override
        public List<IpProtocolStatsEntry> getRxIpProtocolStats() {
            return this.ipProtocolStatsList;
        }

        @Override
        public List<VirtualPortStatsEntry> getRxSourceVirtualPortStats() {
            return this.sourceVirtualPortStatsList;
        }

        @Override
        public List<VirtualPortStatsEntry> getRxDestinationVirtualPortStats() {
            return this.destinationVirtualPortStatsList;
        }

        public void addEthernetType(final EthernetType et, long packetLength) {
            boolean added = false;
            for (EthernetTypeStatsEntry etse : this.ethernetTypeStatsList) {
                if (etse.getEthernetType().equals(et)) {
                    etse.incrementPacketCount();
                    etse.incrementByteCount(packetLength);
                    added = true;
                    break;
                }
            }
            if (!added) {
                EthernetTypeStatsEntry etse = new EthernetTypeStatsEntry() {

                    private long packetCount = 0;
                    private long byteCount = 0;

                    @Override
                    public EthernetType getEthernetType() {
                        return et;
                    }

                    @Override
                    public long getPacketCount() {
                        return this.packetCount;
                    }

                    @Override
                    public long getByteCount() {
                        return this.byteCount;
                    }

                    @Override
                    public void incrementPacketCount() {
                        this.packetCount++;
                    }

                    @Override
                    public void incrementByteCount(long length) {
                        this.byteCount += length;
                    }
                };
                etse.incrementPacketCount();
                etse.incrementByteCount(packetLength);
                this.ethernetTypeStatsList.add(etse);

                Collections.sort(this.ethernetTypeStatsList, new Comparator<EthernetTypeStatsEntry>() {

                    @Override
                    public int compare(EthernetTypeStatsEntry o1, EthernetTypeStatsEntry o2) {
                        return o1.getEthernetType().toString().compareTo(o2.getEthernetType().toString());
                    }
                });
            }
        }

        public void addIpProtocol(final IpProtocol ip, long packetLength) {
            boolean added = false;
            for (IpProtocolStatsEntry ipse : this.ipProtocolStatsList) {
                if (ipse.getIpProtocol().equals(ip)) {
                    ipse.incrementPacketCount();
                    ipse.incrementByteCount(packetLength);
                    added = true;
                    break;
                }
            }
            if (!added) {
                IpProtocolStatsEntry ipse = new IpProtocolStatsEntry() {

                    private long packetCount = 0;
                    private long byteCount = 0;

                    @Override
                    public IpProtocol getIpProtocol() {
                        return ip;
                    }

                    @Override
                    public long getPacketCount() {
                        return this.packetCount;
                    }

                    @Override
                    public long getByteCount() {
                        return this.byteCount;
                    }

                    @Override
                    public void incrementPacketCount() {
                        this.packetCount++;
                    }

                    @Override
                    public void incrementByteCount(long length) {
                        this.byteCount += length;
                    }
                };
                ipse.incrementPacketCount();
                ipse.incrementByteCount(packetLength);
                this.ipProtocolStatsList.add(ipse);

                Collections.sort(this.ipProtocolStatsList, new Comparator<IpProtocolStatsEntry>() {

                    @Override
                    public int compare(IpProtocolStatsEntry o1, IpProtocolStatsEntry o2) {
                        return o1.getIpProtocol().toString().compareTo(o2.getIpProtocol().toString());
                    }
                });
            }
        }

        public void addSourceVirtualPortStatsEntry(final int portNumber, long packetLength) {
            boolean added = false;
            for (VirtualPortStatsEntry vpse : this.sourceVirtualPortStatsList) {
                if (vpse.getPortNumber() == portNumber) {
                    vpse.incrementPacketCount();
                    vpse.incrementByteCount(packetLength);
                    added = true;
                    break;
                }
            }
            if (!added) {
                VirtualPortStatsEntry vpse = new VirtualPortStatsEntry() {

                    private long packetCount = 0;
                    private long byteCount = 0;

                    @Override
                    public long getPacketCount() {
                        return this.packetCount;
                    }

                    @Override
                    public long getByteCount() {
                        return this.byteCount;
                    }

                    @Override
                    public void incrementPacketCount() {
                        this.packetCount++;
                    }

                    @Override
                    public void incrementByteCount(long length) {
                        this.byteCount += length;
                    }

                    @Override
                    public int getPortNumber() {
                        return portNumber;
                    }
                };
                vpse.incrementPacketCount();
                vpse.incrementByteCount(packetLength);
                this.sourceVirtualPortStatsList.add(vpse);

                Collections.sort(this.sourceVirtualPortStatsList, new Comparator<VirtualPortStatsEntry>() {

                    @Override
                    public int compare(VirtualPortStatsEntry o1, VirtualPortStatsEntry o2) {
                        return o1.getPortNumber() < o2.getPortNumber() ? -1 : o1.getPortNumber() == o2.getPortNumber() ? 0 : 1;
                    }
                });
            }
        }

        public void addDestinationVirtualPortStatsEntry(final int portNumber, long packetLength) {
            boolean added = false;
            for (VirtualPortStatsEntry vpse : this.destinationVirtualPortStatsList) {
                if (vpse.getPortNumber() == portNumber) {
                    vpse.incrementPacketCount();
                    vpse.incrementByteCount(packetLength);
                    added = true;
                    break;
                }
            }
            if (!added) {
                VirtualPortStatsEntry vpse = new VirtualPortStatsEntry() {

                    private long packetCount = 0;
                    private long byteCount = 0;

                    @Override
                    public long getPacketCount() {
                        return this.packetCount;
                    }

                    @Override
                    public long getByteCount() {
                        return this.byteCount;
                    }

                    @Override
                    public void incrementPacketCount() {
                        this.packetCount++;
                    }

                    @Override
                    public void incrementByteCount(long length) {
                        this.byteCount += length;
                    }

                    @Override
                    public int getPortNumber() {
                        return portNumber;
                    }
                };
                vpse.incrementPacketCount();
                vpse.incrementByteCount(packetLength);
                this.destinationVirtualPortStatsList.add(vpse);

                Collections.sort(this.destinationVirtualPortStatsList, new Comparator<VirtualPortStatsEntry>() {

                    @Override
                    public int compare(VirtualPortStatsEntry o1, VirtualPortStatsEntry o2) {
                        return o1.getPortNumber() < o2.getPortNumber() ? -1 : o1.getPortNumber() == o2.getPortNumber() ? 0 : 1;
                    }
                });
            }
        }
    }

    private Pcap pcap;
    private final PcapIf pcapInterface;
    private SwitchController switchController;
    private Receiver receiver;
    private Thread receiverThread;
    private RealtimeStats realtimeStats;
    private Thread realtimeStatsThread;
    private final NicStatsImpl stats = new NicStatsImpl();

    public NetworkInterface(PcapIf iface) {
        this.pcapInterface = iface;
    }

    public PcapIf getPcapInterface() {
        return pcapInterface;
    }

    public void startSwitchport(SwitchController controller) {
        this.switchController = controller;

        if (pcap == null) {
            StringBuilder errbuf = new StringBuilder();
            this.logger.debug("Starting packet receiver for interface " + this.pcapInterface.getName());
            int snaplen = 64 * 1024;
            int flags = Pcap.MODE_PROMISCUOUS;
            int timeout = 10 * 1000;
            this.pcap = Pcap.openLive(this.pcapInterface.getName(), snaplen, flags, timeout, errbuf);

            if (pcap == null) {
                this.logger.error("Failed to open device for capture: " + errbuf.toString());
                return;
            }
        }

        this.receiver = new Receiver();
        this.receiverThread = new Thread(this.receiver);
        this.receiverThread.start();

        this.realtimeStats = new RealtimeStats();
        this.realtimeStatsThread = new Thread(this.realtimeStats);
        this.realtimeStatsThread.start();

        this.active = true;
    }

    public void stopSwitchport() {
        this.receiver.stop();
        this.realtimeStats.stop();

        List<MacAddress> toDelete = new ArrayList<>();

        for (Map.Entry<MacAddress, MacTableEntry> mte : this.switchController.getForwarder().getMacTable().entrySet()) {
            if (mte.getValue().getNetworkInterface().equals(this)) {
                toDelete.add(mte.getKey());
            }
        }
        for (MacAddress ma : toDelete) {
            this.switchController.getForwarder().removeMacTableEntry(ma);
        }

        this.active = false;
        this.pcap.close();
        this.pcap = null;
        this.switchController = null;
    }

    public void sendPacket(byte[] buffer) {
        if (this.active) {
            this.pcap.sendPacket(buffer);
            this.stats.txPackets += 1;
            this.stats.txBytes += buffer.length;
        } else {
            this.logger.warn("Ignoring packet transmit request on inactive interface " + this.getPcapInterface().getName());
        }
    }

    public NicStats getStats() {
        return this.stats;
    }
}
