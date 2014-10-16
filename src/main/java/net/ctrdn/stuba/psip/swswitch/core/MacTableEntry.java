package net.ctrdn.stuba.psip.swswitch.core;

import net.ctrdn.stuba.psip.swswitch.common.MacAddress;
import net.ctrdn.stuba.psip.swswitch.nic.NetworkInterface;
import java.util.Date;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

final public class MacTableEntry {
    
    private final Logger logger = LoggerFactory.getLogger(MacTableEntry.class);
    private final MacAddress macAddress;
    private final NetworkInterface networkInterface;
    private Date lastSeenDate;
    private long txPackets = 0;
    private long rxPackets = 0;
    private long txBytes = 0;
    private long rxBytes = 0;
    
    public MacTableEntry(MacAddress address, NetworkInterface networkInterface) {
        this.macAddress = address;
        this.networkInterface = networkInterface;
        this.updateLastSeenDate();
    }
    
    public void updateLastSeenDate() {
        this.lastSeenDate = new Date();
    }
    
    public void incrementRxPacketCount() {
        this.rxPackets += 1;
    }
    
    public void incrementTxPacketCount() {
        this.txPackets += 1;
    }
    
    public void incrementTxByteCount(long bytes) {
        this.txBytes += bytes;
    }
    
    public void incrementRxByteCount(long bytes) {
        this.rxBytes += bytes;
    }
    
    public MacAddress getMacAddress() {
        return macAddress;
    }
    
    public NetworkInterface getNetworkInterface() {
        return networkInterface;
    }
    
    public Date getLastSeenDate() {
        return lastSeenDate;
    }
    
    public long getTxPackets() {
        return txPackets;
    }
    
    public long getRxPackets() {
        return rxPackets;
    }
    
    public long getTxBytes() {
        return txBytes;
    }
    
    public long getRxBytes() {
        return rxBytes;
    }
    
    public void resetStats() {
        this.txPackets = 0;
        this.txBytes = 0;
        this.rxPackets = 0;
        this.rxBytes = 0;
        this.logger.info("Forwarding table entry " + this.macAddress.toString() + " stats has been reset");
    }
}
