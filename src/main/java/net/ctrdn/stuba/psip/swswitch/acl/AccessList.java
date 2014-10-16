package net.ctrdn.stuba.psip.swswitch.acl;

import java.util.Map;
import org.jnetpcap.packet.PcapPacket;

public interface AccessList {

    public AccessListAction evaluate(PcapPacket packet);

    public void add(AccessListEntry entry);

    public void remove(AccessListEntry entry);

    public AccessListEntry[] getEntries();

    public byte[] getId();

    public String getName();

    public void setName(String name);

    public Map<String, String> getConfigurationEntries();

    public int getFreeIndex();

    public int getLastOrderKey();

    public void sort();

    public AccessListEntry getEntryById(int id);
}
