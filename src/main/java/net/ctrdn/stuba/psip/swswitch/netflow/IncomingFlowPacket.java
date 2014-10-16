package net.ctrdn.stuba.psip.swswitch.netflow;

import net.ctrdn.stuba.psip.swswitch.core.IncomingFrame;
import net.ctrdn.stuba.psip.swswitch.nic.NetworkInterface;

public interface IncomingFlowPacket {

    public IncomingFrame getIncomingFrame();

    public NetworkInterface getEgressInterface();
}
