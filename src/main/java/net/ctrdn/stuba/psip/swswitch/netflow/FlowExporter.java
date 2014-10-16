package net.ctrdn.stuba.psip.swswitch.netflow;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedDeque;
import net.ctrdn.stuba.psip.swswitch.common.IpAddress;
import net.ctrdn.stuba.psip.swswitch.common.Unsigned;
import net.ctrdn.stuba.psip.swswitch.core.IncomingFrame;
import net.ctrdn.stuba.psip.swswitch.core.SwitchController;
import net.ctrdn.stuba.psip.swswitch.nic.NetworkInterface;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FlowExporter implements Runnable {

    private final Logger logger = LoggerFactory.getLogger(FlowExporter.class);
    private final SwitchController switchController;
    private final byte nfEngineType = 1;
    private final byte nfEngineId = 1;
    private final int sleepTime = 1000;

    private IpAddress nfDestinationAddress;
    private int nfDestinationPort;
    private int flowTimeout;
    private int exportInterval;

    private DatagramSocket sourceSocket;
    private Date startupDate;
    private boolean running = true;
    private final List<FlowEntry> entryList = new ArrayList<>();
    private final Queue<IncomingFlowPacket> incomingFrameQueue = new ConcurrentLinkedDeque<>();
    private long packetsProcessed = 0;
    private long totalFlowsSeen = 0;
    private long totalFlowsExpired = 0;
    private long totalNetflowMessagesSent = 0;
    private long totalPacketsProcessed = 0;
    private long totalPacketsDiscarded = 0;

    public FlowExporter(SwitchController switchController, IpAddress destinationAddress, int destinationPort, int flowTimeout, int exportInterval) {
        this.switchController = switchController;
        this.nfDestinationAddress = destinationAddress;
        this.nfDestinationPort = destinationPort;
        this.flowTimeout = flowTimeout;
        this.exportInterval = exportInterval;
    }

    @Override
    public void run() {
        try {
            this.startupDate = new Date();
            this.sourceSocket = new DatagramSocket();
            this.logger.info("Flow exporter started");
            while (this.running) {
                while (!this.incomingFrameQueue.isEmpty()) {
                    IncomingFlowPacket ifp = this.incomingFrameQueue.poll();
                    boolean added = false;
                    for (FlowEntry fe : this.entryList) {
                        added = fe.addIfMatches(ifp.getIncomingFrame());
                        if (added) {
                            break;
                        }
                    }
                    if (!added) {
                        try {
                            FlowEntry fe = new FlowEntry(ifp.getIncomingFrame(), ifp.getEgressInterface());
                            this.entryList.add(fe);
                            this.packetsProcessed++;
                            this.totalPacketsProcessed++;
                            this.totalFlowsSeen++;
                            this.logger.debug("Spawned new flow");
                        } catch (UnsupportedPacketException iex) {
                            this.totalPacketsDiscarded++;
                            this.logger.trace("Unsupported packet received in flow exporter", iex);
                        }
                    } else {
                        this.packetsProcessed++;
                        this.totalPacketsProcessed++;
                    }
                }
                if (this.packetsProcessed >= this.getExportInterval()) {
                    this.transmit();
                }
                Thread.sleep(this.sleepTime);
            }
            if (this.packetsProcessed > 0) {
                this.transmit();
            }
            this.sourceSocket.close();
        } catch (InterruptedException ex) {
            this.logger.error("Interrupter", ex);
        } catch (SocketException ex) {
            this.logger.error("Failed to open socket for flow export.", ex);
        }
    }

    private void transmit() {
        try {
            byte[] packet = this.generateNetflowPacket();
            DatagramPacket nfPacket = new DatagramPacket(packet, packet.length, InetAddress.getByAddress(this.getNfDestinationAddress().getAddressBytes()), this.getNfDestinationPort());
            this.sourceSocket.send(nfPacket);
            this.packetsProcessed = 0;
            this.logger.debug("Exported flows to " + this.getNfDestinationAddress().toString() + ":" + this.getNfDestinationPort());
            this.totalNetflowMessagesSent++;
        } catch (IOException iex) {
            this.logger.warn("Failed to send netflow data.", iex);
        }
    }

    private byte[] generateNetflowPacket() throws IOException {
        Date currentDate = new Date();

        List<FlowEntry> flowToExportList = new ArrayList<>();
        List<FlowEntry> expiredFlowList = new ArrayList<>();
        for (FlowEntry fe : this.entryList) {
            if (fe.getCurrentPackets() > 0) {
                if (flowToExportList.size() >= 30) {
                    continue;
                }
                flowToExportList.add(fe);
            } else if (currentDate.getTime() - fe.getLastPacketDate().getTime() >= this.getFlowTimeout()) {
                expiredFlowList.add(fe);
                this.totalFlowsExpired++;
            }
        }

        for (FlowEntry fe : expiredFlowList) {
            this.entryList.remove(fe);
            this.logger.debug("Flow " + fe.toString() + " has expired");
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ByteBuffer flowHeaderBuffer = ByteBuffer.allocate(24);
        Unsigned.putUnsignedShort(flowHeaderBuffer, 5);
        Unsigned.putUnsignedShort(flowHeaderBuffer, flowToExportList.size());
        Unsigned.putUnsignedInt(flowHeaderBuffer, currentDate.getTime() - this.startupDate.getTime());
        Unsigned.putUnsignedInt(flowHeaderBuffer, currentDate.getTime() / 1000);
        Unsigned.putUnsignedInt(flowHeaderBuffer, currentDate.getTime() - ((currentDate.getTime() / 1000) * 1000) * 1000000);
        Unsigned.putUnsignedInt(flowHeaderBuffer, this.getTotalFlowsSeen());
        flowHeaderBuffer.put(this.nfEngineType);
        flowHeaderBuffer.put(this.nfEngineId);

        byte[] samplingInterval = new byte[2];
        samplingInterval[0] = (byte) 0xC0;
        samplingInterval[1] = (byte) 0x00;
        flowHeaderBuffer.put(samplingInterval);

        baos.write(flowHeaderBuffer.array());
        for (FlowEntry fe : flowToExportList) {
            byte[] buff = fe.toNetflowV5ByteBuffer(this).array();
            baos.write(buff);
            fe.resetCounters();
        }
        return baos.toByteArray();
    }

    public void stop() {
        this.running = false;
    }

    public void newPacket(final IncomingFrame incomingFrame, final NetworkInterface egressInterface) {
        if (!this.running) {
            return;
        }
        this.incomingFrameQueue.offer(new IncomingFlowPacket() {

            @Override
            public IncomingFrame getIncomingFrame() {
                return incomingFrame;
            }

            @Override
            public NetworkInterface getEgressInterface() {
                return egressInterface;
            }
        });
    }

    protected SwitchController getSwitchController() {
        return switchController;
    }

    public Date getStartupDate() {
        return startupDate;
    }

    public void setNfDestinationAddress(IpAddress nfDestinationAddress) {
        this.nfDestinationAddress = nfDestinationAddress;
    }

    public void setNfDestinationPort(int nfDestinationPort) {
        this.nfDestinationPort = nfDestinationPort;
    }

    public void setFlowTimeout(int flowTimeout) {
        this.flowTimeout = flowTimeout;
    }

    public void setExportInterval(int exportInterval) {
        this.exportInterval = exportInterval;
    }

    public IpAddress getNfDestinationAddress() {
        return nfDestinationAddress;
    }

    public int getNfDestinationPort() {
        return nfDestinationPort;
    }

    public int getFlowTimeout() {
        return flowTimeout;
    }

    public int getExportInterval() {
        return exportInterval;
    }

    public long getTotalFlowsSeen() {
        return totalFlowsSeen;
    }

    public long getTotalFlowsExpired() {
        return totalFlowsExpired;
    }

    public long getTotalNetflowMessagesSent() {
        return totalNetflowMessagesSent;
    }

    public long getTotalPacketsProcessed() {
        return totalPacketsProcessed;
    }

    public long getTotalPacketsDiscarded() {
        return totalPacketsDiscarded;
    }
}
