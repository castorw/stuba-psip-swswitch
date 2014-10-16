package net.ctrdn.stuba.psip.swswitch.core;

import net.ctrdn.stuba.psip.swswitch.common.MacAddress;
import net.ctrdn.stuba.psip.swswitch.nic.NetworkInterface;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import net.ctrdn.stuba.psip.swswitch.acl.AccessList;
import net.ctrdn.stuba.psip.swswitch.acl.AccessListAction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Forwarder implements Runnable {

    private int macTableEntryTimeout = 600000;
    private final Logger logger = LoggerFactory.getLogger(Forwarder.class);
    private final SwitchController switchController;
    private final Map<MacAddress, MacTableEntry> macTable = new ConcurrentHashMap<>();

    public Forwarder(SwitchController controller) {
        this.switchController = controller;
    }

    @Override
    public void run() {
        try {
            while (true) {
                for (Map.Entry<MacAddress, MacTableEntry> entry : this.getMacTable().entrySet()) {
                    if (new Date().getTime() - entry.getValue().getLastSeenDate().getTime() >= this.macTableEntryTimeout) {
                        this.logger.info("Forwarding table entry " + entry.getValue().getMacAddress().toString() + " on interface " + entry.getValue().getNetworkInterface().getPcapInterface().getName() + " removed due to timeout");
                        this.getMacTable().remove(entry.getKey());
                    }
                }
                while (!this.switchController.getIncomingFrameQueue().isEmpty()) {
                    IncomingFrame iframe = this.switchController.getIncomingFrameQueue().poll();
                    MacTableEntry sourceMacTableEntry;
                    if (!this.macTable.containsKey(iframe.getSourceMacAddress())) {
                        this.logger.info("Hardware address " + iframe.getSourceMacAddress().toString() + " not found in forwarding table. Learning.");
                        sourceMacTableEntry = this.learnHost(iframe);
                    } else {
                        sourceMacTableEntry = this.getMacTable().get(iframe.getSourceMacAddress());
                        if (!sourceMacTableEntry.getNetworkInterface().equals(iframe.getNetworkInterface())) {
                            this.logger.warn("Source port mismatch, removing source and destination entry from forwarding table (learned_if=" + sourceMacTableEntry.getNetworkInterface().getPcapInterface().getName() + ", recv_if=" + iframe.getNetworkInterface().getPcapInterface().getName() + ", srcmac=" + iframe.getSourceMacAddress().toString() + ")");
                            this.unlearnSource(iframe);
                            this.unlearnDestination(iframe);
                            sourceMacTableEntry = this.learnHost(iframe);
                        } else {
                            sourceMacTableEntry.updateLastSeenDate();
                        }
                    }
                    MacTableEntry destinationMacTableEntry = this.resolveMacTableEntry(iframe.getDestinationMacAddress());
                    if (!processAccessList(sourceMacTableEntry.getNetworkInterface(), (destinationMacTableEntry == null) ? null : destinationMacTableEntry.getNetworkInterface(), iframe)) {
                        continue;
                    }
                    if (destinationMacTableEntry == null) {
                        this.logger.info("Destination " + iframe.getDestinationMacAddress().toString() + " not found in forwarding table. Flooding.");
                        for (NetworkInterface nic : this.switchController.getInterfaceList()) {
                            if (nic.isActive() && !nic.equals(iframe.getNetworkInterface())) {
                                nic.sendPacket(iframe.getPcapPacket().getByteArray(0, iframe.getPcapPacket().getCaptureHeader().caplen()));
                            }
                        }
                    } else {
                        if (destinationMacTableEntry.getNetworkInterface().equals(iframe.getNetworkInterface())) {
                            this.logger.warn("Not forwarding packet from " + iframe.getSourceMacAddress().toString() + " on " + sourceMacTableEntry.getNetworkInterface().getPcapInterface().getName() + " -> " + iframe.getDestinationMacAddress().toString() + " on " + destinationMacTableEntry.getNetworkInterface().getPcapInterface().getName() + " - same interface");
                        } else {
                            this.logger.debug("Forwarding packet from " + iframe.getSourceMacAddress().toString() + " on " + sourceMacTableEntry.getNetworkInterface().getPcapInterface().getName() + " -> " + iframe.getDestinationMacAddress().toString() + " on " + destinationMacTableEntry.getNetworkInterface().getPcapInterface().getName() + "");
                            destinationMacTableEntry.getNetworkInterface().sendPacket(iframe.getPcapPacket().getByteArray(0, iframe.getPcapPacket().getCaptureHeader().caplen()));
                            if (this.switchController.getFlowExporter() != null) {
                                this.switchController.getFlowExporter().newPacket(iframe, destinationMacTableEntry.getNetworkInterface());
                            }
                        }
                    }
                    sourceMacTableEntry.incrementTxPacketCount();
                    sourceMacTableEntry.incrementTxByteCount(iframe.getPcapPacket().getCaptureHeader().caplen());
                    if (destinationMacTableEntry != null) {
                        destinationMacTableEntry.incrementRxPacketCount();
                        destinationMacTableEntry.incrementRxByteCount(iframe.getPcapPacket().getCaptureHeader().caplen());
                    }
                    if (this.switchController.getIncomingFrameQueue().isEmpty()) {
                        synchronized (this.switchController.getIncomingFrameLock()) {
                            this.switchController.getIncomingFrameLock().wait(1000);
                        }
                    }
                }
            }
        } catch (InterruptedException ex) {
            this.logger.error("Interrupted", ex);
        }
    }

    private MacTableEntry resolveMacTableEntry(MacAddress macAddress) {
        if (this.getMacTable().containsKey(macAddress)) {
            return this.getMacTable().get(macAddress);
        }
        return null;
    }

    private void unlearnSource(IncomingFrame iframe) {
        MacTableEntry mte = this.resolveMacTableEntry(iframe.getSourceMacAddress());
        if (mte != null) {
            this.getMacTable().remove(iframe.getSourceMacAddress());
            this.logger.debug("Unlearned host " + iframe.getSourceMacAddress() + " from interface " + mte.getNetworkInterface().getPcapInterface().getName());
        }
    }

    private void unlearnDestination(IncomingFrame iframe) {
        MacTableEntry mte = this.resolveMacTableEntry(iframe.getSourceMacAddress());
        if (mte != null) {
            this.getMacTable().remove(iframe.getDestinationMacAddress());
            this.logger.debug("Unlearned host " + iframe.getDestinationMacAddress() + " from interface " + mte.getNetworkInterface().getPcapInterface().getName());
        }
    }

    private MacTableEntry learnHost(IncomingFrame iframe) {
        MacTableEntry mte = new MacTableEntry(iframe.getSourceMacAddress(), iframe.getNetworkInterface());
        this.getMacTable().put(iframe.getSourceMacAddress(), mte);
        this.logger.debug("Learned host " + iframe.getDestinationMacAddress() + " on interface " + mte.getNetworkInterface().getPcapInterface().getName());
        return mte;
    }

    private boolean processAccessList(NetworkInterface ingressIf, NetworkInterface egressIf, IncomingFrame iframe) {
        AccessList ingressAcl = ingressIf.getIngressAccessList();
        AccessListAction ingressAction = (ingressAcl != null) ? ingressAcl.evaluate(iframe.getPcapPacket()) : AccessListAction.PERMIT;
        boolean ingressAllow = ingressAction == null || ingressAction == AccessListAction.PERMIT;

        AccessList egressAcl = (egressIf == null) ? null : egressIf.getEgressAccessList();
        AccessListAction egressAction = (egressAcl != null) ? egressAcl.evaluate(iframe.getPcapPacket()) : AccessListAction.PERMIT;
        boolean egressAllow = egressAction == null || egressAction == AccessListAction.PERMIT;

        return ingressAllow && egressAllow;
    }

    public int getMacTableEntryTimeout() {
        return macTableEntryTimeout;
    }

    public void setMacTableEntryTimeout(int macTableEntryTimeout) {
        this.macTableEntryTimeout = macTableEntryTimeout;
    }

    public Map<MacAddress, MacTableEntry> getMacTable() {
        return macTable;
    }

    public void removeMacTableEntry(MacAddress addr) {
        if (this.macTable.containsKey(addr)) {
            this.macTable.remove(addr);
            this.logger.info("Removed forwarding table entry " + addr.toString());
        }
    }
}
