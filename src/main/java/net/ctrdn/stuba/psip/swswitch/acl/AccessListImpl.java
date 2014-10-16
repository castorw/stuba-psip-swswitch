package net.ctrdn.stuba.psip.swswitch.acl;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import net.ctrdn.stuba.psip.swswitch.common.DataTypeHelpers;
import org.jnetpcap.packet.PcapPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AccessListImpl implements AccessList {

    private final Logger logger = LoggerFactory.getLogger(AccessList.class);
    private final byte[] id;
    private String name;
    private final List<AccessListEntry> entryList = new ArrayList<>();

    public AccessListImpl(byte[] id) {
        this(id, null);
    }

    public AccessListImpl(byte[] id, String name) {
        this.id = id;
        this.name = name;
    }

    @Override
    public AccessListAction evaluate(PcapPacket packet) {
        for (AccessListEntry ale : this.entryList) {
            AccessListAction ala = ale.evaluate(packet);
            if (ala != null) {
                this.logger.debug("[" + DataTypeHelpers.byteArrayToHexString(this.id) + "] " + DataTypeHelpers.byteArrayToHexString(packet.getByteArray(0, 6)) + " -> " + DataTypeHelpers.byteArrayToHexString(packet.getByteArray(6, 6)) + ", action " + ala.toString() + " by " + ale.getId());
                return ala;
            }
        }
        this.logger.debug("[" + DataTypeHelpers.byteArrayToHexString(this.id) + "] " + DataTypeHelpers.byteArrayToHexString(packet.getByteArray(0, 6)) + " -> " + DataTypeHelpers.byteArrayToHexString(packet.getByteArray(6, 6)) + ", no match");
        return null;
    }

    @Override
    public void add(AccessListEntry entry) {
        this.entryList.add(entry);
    }

    @Override
    public void remove(AccessListEntry entry) {
        if (this.entryList.contains(entry)) {
            this.entryList.remove(entry);
        }
    }

    @Override
    public byte[] getId() {
        return id;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public void setName(String name) {
        this.name = name;
    }

    @Override
    public AccessListEntry[] getEntries() {
        return entryList.toArray(new AccessListEntry[this.entryList.size()]);
    }

    @Override
    public Map<String, String> getConfigurationEntries() {
        String aclPrefix = "acl." + DataTypeHelpers.byteArrayToHexString(this.id);
        Map<String, String> config = new HashMap<>();
        config.put(aclPrefix + ".name", this.name);
        for (AccessListEntry entry : this.entryList) {
            Map<String, String> entryConfig = entry.getConfigurationEntries();
            for (Map.Entry<String, String> entryConfigEntry : entryConfig.entrySet()) {
                config.put(entryConfigEntry.getKey(), entryConfigEntry.getValue());
            }
        }
        return config;
    }

    @Override
    public int getFreeIndex() {
        int max = 0;
        for (AccessListEntry e : this.entryList) {
            if (e.getId() > max) {
                max = e.getId();
            }
        }
        return max + 1;
    }

    @Override
    public int getLastOrderKey() {
        int max = 0;
        for (AccessListEntry e : this.entryList) {
            if (e.getOrderKey() > max) {
                max = e.getOrderKey();
            }
        }
        return max + 1;
    }

    @Override
    public void sort() {
        Collections.sort(this.entryList, new Comparator<AccessListEntry>() {

            @Override
            public int compare(AccessListEntry o1, AccessListEntry o2) {
                return (o1.getOrderKey() == o2.getOrderKey()) ? 0 : (o1.getOrderKey() < o2.getOrderKey()) ? -1 : 1;
            }
        });
    }

    @Override
    public AccessListEntry getEntryById(int id) {
        for (AccessListEntry e : this.entryList) {
            if (e.getId() == id) {
                return e;
            }
        }
        return null;
    }

}
