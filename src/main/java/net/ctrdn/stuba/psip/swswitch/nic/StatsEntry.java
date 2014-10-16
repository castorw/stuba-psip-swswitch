package net.ctrdn.stuba.psip.swswitch.nic;

public interface StatsEntry {

    public long getPacketCount();

    public long getByteCount();

    public void incrementPacketCount();

    public void incrementByteCount(long length);
}
