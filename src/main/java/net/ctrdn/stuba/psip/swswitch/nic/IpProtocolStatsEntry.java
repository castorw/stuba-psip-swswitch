package net.ctrdn.stuba.psip.swswitch.nic;

import net.ctrdn.stuba.psip.swswitch.common.IpProtocol;

public interface IpProtocolStatsEntry extends StatsEntry {

    public IpProtocol getIpProtocol();
}
