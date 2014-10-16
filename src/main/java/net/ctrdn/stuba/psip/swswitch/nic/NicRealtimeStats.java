package net.ctrdn.stuba.psip.swswitch.nic;

public interface NicRealtimeStats {

    public long getTxThroughputPackets();

    public long getTxThroughputBytes();

    public long getRxThroughputPackets();

    public long getRxThroughputBytes();
    
    public void reset();
}
