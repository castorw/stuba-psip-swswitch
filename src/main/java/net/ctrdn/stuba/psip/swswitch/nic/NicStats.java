package net.ctrdn.stuba.psip.swswitch.nic;

import java.util.List;

public interface NicStats {

    public long getRxPackets();

    public long getRxBytes();

    public long getTxPackets();

    public long getTxBytes();

    public List<EthernetTypeStatsEntry> getRxEthernetTypeStats();

    public List<IpProtocolStatsEntry> getRxIpProtocolStats();

    public List<VirtualPortStatsEntry> getRxSourceVirtualPortStats();

    public List<VirtualPortStatsEntry> getRxDestinationVirtualPortStats();

    public NicRealtimeStats getRealtimeStats();

    public void reset();
}
