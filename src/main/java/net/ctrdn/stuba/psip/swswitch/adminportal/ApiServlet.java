package net.ctrdn.stuba.psip.swswitch.adminportal;

import java.io.IOException;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import javax.json.Json;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObjectBuilder;
import javax.json.JsonWriter;
import javax.json.stream.JsonGenerator;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import net.ctrdn.stuba.psip.swswitch.common.IpAddress;
import net.ctrdn.stuba.psip.swswitch.common.MacAddress;
import net.ctrdn.stuba.psip.swswitch.core.MacTableEntry;
import net.ctrdn.stuba.psip.swswitch.nic.NetworkInterface;
import net.ctrdn.stuba.psip.swswitch.core.SwitchController;
import net.ctrdn.stuba.psip.swswitch.acl.AccessList;
import net.ctrdn.stuba.psip.swswitch.acl.AccessListAction;
import net.ctrdn.stuba.psip.swswitch.acl.AccessListEntry;
import net.ctrdn.stuba.psip.swswitch.acl.AccessListImpl;
import net.ctrdn.stuba.psip.swswitch.common.EthernetType;
import net.ctrdn.stuba.psip.swswitch.common.IpProtocol;
import net.ctrdn.stuba.psip.swswitch.common.DataTypeHelpers;
import net.ctrdn.stuba.psip.swswitch.nic.EthernetTypeStatsEntry;
import net.ctrdn.stuba.psip.swswitch.nic.IpProtocolStatsEntry;
import net.ctrdn.stuba.psip.swswitch.nic.VirtualPortStatsEntry;

public class ApiServlet extends HttpServlet {

    private final SwitchController switchController;

    public ApiServlet(SwitchController switchController) {
        this.switchController = switchController;
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        response.setContentType("text/json");
        String apiCallName = request.getRequestURI().replace(request.getServletPath() + "/", "");
        JsonObjectBuilder responseJob = Json.createObjectBuilder();

        switch (apiCallName) {
            case "acl.list": {
                JsonArrayBuilder aclJab = Json.createArrayBuilder();
                for (AccessList acl : this.switchController.getAccessLists()) {
                    JsonObjectBuilder aclJob = Json.createObjectBuilder();
                    aclJob.add("Id", DataTypeHelpers.byteArrayToHexString(acl.getId()));
                    if (acl.getName() == null) {
                        aclJob.addNull("Name");
                    } else {
                        aclJob.add("Name", acl.getName());
                    }
                    aclJob.add("EntryCount", acl.getEntries().length);
                    aclJab.add(aclJob);
                }
                responseJob.add("Status", true);
                responseJob.add("AccessListList", aclJab);
                break;
            }
            case "acl.create": {
                String name = request.getParameter("name");
                AccessList newAcl;
                byte[] newAclId = new byte[4];
                Random random = new Random();
                random.nextBytes(newAclId);
                if (name != null && !name.trim().isEmpty()) {
                    newAcl = new AccessListImpl(newAclId, name);
                } else {
                    newAcl = new AccessListImpl(newAclId);
                }
                this.switchController.getAccessLists().add(newAcl);

                responseJob.add("Status", true);
                responseJob.add("AccessListId", DataTypeHelpers.byteArrayToHexString(newAclId));
                this.switchController.writeConfiguration();
                this.switchController.reloadAccessLists();
                break;
            }
            case "acl.delete": {
                String idString = request.getParameter("id");
                byte[] id = DataTypeHelpers.hexStringToByteArray(idString);
                AccessList foundAcl = null;
                for (AccessList acl : this.switchController.getAccessLists()) {
                    if (Arrays.equals(acl.getId(), id)) {
                        foundAcl = acl;
                        break;
                    }
                }
                if (foundAcl != null) {
                    for (NetworkInterface nic : this.switchController.getInterfaceList()) {
                        if (nic.getIngressAccessList() != null && nic.getIngressAccessList().getId() == foundAcl.getId()) {
                            nic.setIngressAccessList(null);
                            this.switchController.getConfig().remove("interface." + nic.getPcapInterface().getName() + ".acl.ingress");
                        }
                        if (nic.getEgressAccessList() != null && nic.getEgressAccessList().getId() == foundAcl.getId()) {
                            nic.setEgressAccessList(null);
                            this.switchController.getConfig().remove("interface." + nic.getPcapInterface().getName() + ".acl.egress");
                        }
                    }

                    this.switchController.getAccessLists().remove(foundAcl);
                    this.switchController.writeConfiguration();
                    this.switchController.reloadAccessLists();
                    responseJob.add("Status", true);
                } else {
                    responseJob.add("Status", false);
                    responseJob.add("Error", "acl not found");
                }

                break;
            }
            case "acl.rename": {
                String idString = request.getParameter("acl-id");
                byte[] id = DataTypeHelpers.hexStringToByteArray(idString);
                AccessList foundAcl = null;
                for (AccessList acl : this.switchController.getAccessLists()) {
                    if (Arrays.equals(acl.getId(), id)) {
                        foundAcl = acl;
                        break;
                    }
                }
                if (foundAcl != null) {
                    String newName = request.getParameter("name");
                    foundAcl.setName(newName.isEmpty() ? null : newName);
                    this.switchController.writeConfiguration();
                    responseJob.add("Status", true);
                } else {
                    responseJob.add("Status", false);
                    responseJob.add("Error", "acl not found");
                }

                break;
            }
            case "acl.entry-create": {
                String idString = request.getParameter("acl-id");
                byte[] id = DataTypeHelpers.hexStringToByteArray(idString);
                AccessList foundAcl = null;
                for (AccessList acl : this.switchController.getAccessLists()) {
                    if (Arrays.equals(acl.getId(), id)) {
                        foundAcl = acl;
                        break;
                    }
                }
                if (foundAcl != null) {
                    String iSrcMac = request.getParameter("src-mac");
                    String iDstMac = request.getParameter("dst-mac");
                    String iEthType = request.getParameter("ether-type");
                    String iSrcIp = request.getParameter("src-ip");
                    String iDstIp = request.getParameter("dst-ip");
                    String iIpProto = request.getParameter("ip-proto");
                    String iSrcPort = request.getParameter("src-port");
                    String iDstPort = request.getParameter("dst-port");
                    String iAction = request.getParameter("action");

                    AccessListEntry entry = new AccessListEntry(foundAcl, foundAcl.getFreeIndex());
                    entry.setOrderKey(foundAcl.getLastOrderKey());
                    entry.setAction(AccessListAction.valueOf(iAction));
                    if (!iSrcMac.trim().isEmpty()) {
                        entry.setSourceMacAddress(MacAddress.fromString(iSrcMac));
                    }
                    if (!iDstMac.trim().isEmpty()) {
                        entry.setDestinationMacAddress(MacAddress.fromString(iDstMac));
                    }
                    if (!iEthType.trim().isEmpty()) {
                        EthernetType ethernetType = EthernetType.valueOf(iEthType);
                        entry.setEthernetType(ethernetType);
                        if (ethernetType == EthernetType.IPV4) {
                            if (!iSrcIp.trim().isEmpty()) {
                                entry.setSourceIpAddress(IpAddress.fromString(iSrcIp));
                            }
                            if (!iDstIp.trim().isEmpty()) {
                                entry.setDestinationIpAddress(IpAddress.fromString(iDstIp));
                            }
                            if (!iIpProto.trim().isEmpty()) {
                                IpProtocol ipProtocol = IpProtocol.valueOf(iIpProto);
                                entry.setIpProtocol(ipProtocol);
                                if (ipProtocol == IpProtocol.TCP || ipProtocol == IpProtocol.UDP) {
                                    if (!iSrcPort.trim().isEmpty()) {
                                        entry.setTcpUdpSourcePort(Integer.parseInt(iSrcPort));
                                    }
                                    if (!iDstPort.isEmpty()) {
                                        entry.setTcpUdpDestinationPort(Integer.parseInt(iDstPort));
                                    }
                                }
                            }
                        }
                    }
                    foundAcl.add(entry);

                    this.switchController.writeConfiguration();
                    this.switchController.reloadAccessLists();
                    responseJob.add("Status", true);
                } else {
                    responseJob.add("Status", false);
                    responseJob.add("Error", "acl not found");
                }

                break;
            }
            case "acl.entry-delete": {
                String aclIdString = request.getParameter("acl-id");
                byte[] aclId = DataTypeHelpers.hexStringToByteArray(aclIdString);

                AccessList foundAcl = null;
                for (AccessList acl : this.switchController.getAccessLists()) {
                    if (Arrays.equals(acl.getId(), aclId)) {
                        foundAcl = acl;
                        break;
                    }
                }
                if (foundAcl == null) {
                    responseJob.add("Status", false);
                    responseJob.add("Error", "acl not found");
                    break;
                }

                Integer entryId = Integer.parseInt(request.getParameter("entry-id"));
                AccessListEntry entry = foundAcl.getEntryById(entryId);
                if (entry == null) {
                    responseJob.add("Status", false);
                    responseJob.add("Error", "acn entry not found");
                    break;
                }

                foundAcl.remove(entry);
                this.switchController.writeConfiguration();
                responseJob.add("Status", true);
                break;
            }
            case "acl.entry-get-list": {
                String aclIdString = request.getParameter("acl-id");
                byte[] aclId = DataTypeHelpers.hexStringToByteArray(aclIdString);

                AccessList foundAcl = null;
                for (AccessList acl : this.switchController.getAccessLists()) {
                    if (Arrays.equals(acl.getId(), aclId)) {
                        foundAcl = acl;
                        break;
                    }
                }

                if (foundAcl == null) {
                    responseJob.add("Status", false);
                    responseJob.add("Error", "acl not found");
                    break;
                }

                JsonArrayBuilder entryJab = Json.createArrayBuilder();
                for (AccessListEntry aclEntry : foundAcl.getEntries()) {
                    JsonObjectBuilder entryJob = Json.createObjectBuilder();
                    entryJob.add("Id", aclEntry.getId());
                    entryJob.add("OrderKey", aclEntry.getOrderKey());
                    this.insertToJsonObject(entryJob, "SourceMac", aclEntry.getSourceMacAddress());
                    this.insertToJsonObject(entryJob, "DestinationMac", aclEntry.getDestinationMacAddress());
                    this.insertToJsonObject(entryJob, "EtherType", aclEntry.getEthernetType());
                    this.insertToJsonObject(entryJob, "SourceIp", aclEntry.getSourceIpAddress());
                    this.insertToJsonObject(entryJob, "DestinationIp", aclEntry.getDestinationIpAddress());
                    this.insertToJsonObject(entryJob, "IpProtocol", aclEntry.getIpProtocol());
                    this.insertToJsonObject(entryJob, "SourcePort", aclEntry.getTcpUdpSourcePort());
                    this.insertToJsonObject(entryJob, "DestinationPort", aclEntry.getTcpUdpDestinationPort());
                    this.insertToJsonObject(entryJob, "Action", aclEntry.getAction());
                    entryJob.add("HitCount", aclEntry.getHitCount());
                    entryJab.add(entryJob);
                }

                responseJob.add("Status", true);
                responseJob.add("EntryList", entryJab);
                break;
            }
            case "acl.entry-reorder": {
                String aclIdString = request.getParameter("acl-id");
                byte[] aclId = DataTypeHelpers.hexStringToByteArray(aclIdString);

                AccessList foundAcl = null;
                for (AccessList acl : this.switchController.getAccessLists()) {
                    if (Arrays.equals(acl.getId(), aclId)) {
                        foundAcl = acl;
                        break;
                    }
                }
                if (foundAcl == null) {
                    responseJob.add("Status", false);
                    responseJob.add("Error", "acl not found");
                    break;
                }

                Integer entryId = Integer.parseInt(request.getParameter("entry-id"));
                Integer entryAfterId = (request.getParameter("entry-place-after").trim().isEmpty()) ? null : Integer.parseInt(request.getParameter("entry-place-after"));

                if (entryAfterId == null) {
                    boolean doChange = false;
                    foundAcl.getEntryById(entryId).setOrderKey(0);
                    for (AccessListEntry e : foundAcl.getEntries()) {
                        if (e.getId() == entryId) {
                            continue;
                        }
                        if (e.getOrderKey() == 0) {
                            doChange = true;
                        }
                        if (doChange) {
                            e.setOrderKey(e.getOrderKey() + 1);
                        }
                    }
                } else {
                    AccessListEntry entry = foundAcl.getEntryById(entryId);
                    AccessListEntry entryAfter = foundAcl.getEntryById(entryAfterId);
                    List<AccessListEntry> list = new ArrayList<>();
                    for (AccessListEntry e : foundAcl.getEntries()) {
                        if (e.getId() == entryId) {
                            continue;
                        }
                        list.add(e);
                        if (e.getId() == entryAfter.getId()) {

                            list.add(entry);
                        }
                    }
                    int i = 0;
                    for (AccessListEntry e : list) {
                        e.setOrderKey(i);
                        i++;
                    }
                }

                foundAcl.sort();
                this.switchController.writeConfiguration();
                responseJob.add("Status", true);
                break;
            }

            case "switch.interface-config-get": {
                JsonArrayBuilder interfaceJab = Json.createArrayBuilder();
                for (NetworkInterface nic : this.switchController.getInterfaceList()) {
                    JsonObjectBuilder interfaceJob = Json.createObjectBuilder();
                    interfaceJob.add("Name", nic.getPcapInterface().getName());
                    if (nic.getPcapInterface().getDescription() != null) {
                        interfaceJob.add("Description", nic.getPcapInterface().getDescription());
                    } else {
                        interfaceJob.addNull("Description");
                    }
                    interfaceJob.add("SwitchportStatus", nic.isActive());
                    if (nic.getIngressAccessList() != null) {
                        JsonObjectBuilder aclJob = Json.createObjectBuilder();
                        aclJob.add("Id", DataTypeHelpers.byteArrayToHexString(nic.getIngressAccessList().getId()));
                        aclJob.add("Name", nic.getIngressAccessList().getName());
                        interfaceJob.add("IngressAccessList", aclJob);
                    } else {
                        interfaceJob.addNull("IngressAccessList");
                    }

                    if (nic.getEgressAccessList() != null) {
                        JsonObjectBuilder aclJob = Json.createObjectBuilder();
                        aclJob.add("Id", DataTypeHelpers.byteArrayToHexString(nic.getEgressAccessList().getId()));
                        aclJob.add("Name", nic.getEgressAccessList().getName());
                        interfaceJob.add("EgressAccessList", aclJob);
                    } else {
                        interfaceJob.addNull("EgressAccessList");
                    }

                    interfaceJab.add(interfaceJob);
                }
                responseJob.add("Status", true);
                responseJob.add("InterfaceList", interfaceJab);
                break;
            }

            case "switch.interface-config-set": {
                String ifName = request.getParameter("name");
                NetworkInterface nic = null;
                for (NetworkInterface xnic : this.switchController.getInterfaceList()) {
                    if (xnic.getPcapInterface().getName().equals(ifName)) {
                        nic = xnic;
                        break;
                    }
                }
                if (nic == null) {
                    responseJob.add("Status", false);
                    responseJob.add("Error", "interface not found");
                    break;
                }

                String iEnabledString = request.getParameter("enabled");
                boolean iEnabled = (iEnabledString.equals("true"));
                String iIngressAclId = request.getParameter("ingress-acl");
                String iEgressAclId = request.getParameter("egress-acl");

                if (!iIngressAclId.trim().isEmpty()) {
                    byte[] aclId = DataTypeHelpers.hexStringToByteArray(iIngressAclId);
                    AccessList acl = this.switchController.getAclById(aclId);
                    if (acl == null) {
                        responseJob.add("Status", false);
                        responseJob.add("Error", "ingress acl not found");
                        break;
                    } else {
                        nic.setIngressAccessList(acl);
                        this.switchController.getConfig().setProperty("interface." + ifName + ".acl.ingress", iIngressAclId);
                    }
                } else {
                    nic.setIngressAccessList(null);
                    this.switchController.getConfig().remove("interface." + ifName + ".acl.ingress");
                }

                if (!iEgressAclId.trim().isEmpty()) {
                    byte[] aclId = DataTypeHelpers.hexStringToByteArray(iEgressAclId);
                    AccessList acl = this.switchController.getAclById(aclId);
                    if (acl == null) {
                        responseJob.add("Status", false);
                        responseJob.add("Error", "egress acl not found");
                        break;
                    } else {
                        nic.setEgressAccessList(acl);
                        this.switchController.getConfig().setProperty("interface." + ifName + ".acl.egress", iEgressAclId);
                    }
                } else {
                    nic.setEgressAccessList(null);
                    this.switchController.getConfig().remove("interface." + ifName + ".acl.egress");
                }

                if (iEnabled && !nic.isActive()) {
                    this.switchController.getConfig().setProperty("interface." + ifName + ".switchport.enabled", "true");
                    nic.startSwitchport(this.switchController);
                } else if (!iEnabled && nic.isActive()) {
                    this.switchController.getConfig().setProperty("interface." + ifName + ".switchport.enabled", "false");
                    nic.stopSwitchport();
                }

                this.switchController.writeConfiguration();

                responseJob.add("Status", true);
                break;
            }

            case "switch.interface-status-get": {
                JsonArrayBuilder interfaceJab = Json.createArrayBuilder();
                for (NetworkInterface nic : this.switchController.getInterfaceList()) {
                    JsonObjectBuilder interfaceJob = Json.createObjectBuilder();
                    interfaceJob.add("Name", nic.getPcapInterface().getName());
                    if (nic.getPcapInterface().getDescription() != null) {
                        interfaceJob.add("Description", nic.getPcapInterface().getDescription());
                    } else {
                        interfaceJob.addNull("Description");
                    }
                    interfaceJob.add("SwitchportStatus", nic.isActive());
                    if (nic.isActive()) {
                        interfaceJob.add("TxPacketCount", nic.getStats().getTxPackets());
                        interfaceJob.add("TxByteCount", nic.getStats().getTxBytes());
                        interfaceJob.add("RxPacketCount", nic.getStats().getRxPackets());
                        interfaceJob.add("RxByteCount", nic.getStats().getRxBytes());
                        interfaceJob.add("TxPacketThroughput", nic.getStats().getRealtimeStats().getTxThroughputPackets());
                        interfaceJob.add("TxByteThroughput", nic.getStats().getRealtimeStats().getTxThroughputBytes());
                        interfaceJob.add("RxPacketThroughput", nic.getStats().getRealtimeStats().getRxThroughputPackets());
                        interfaceJob.add("RxByteThroughput", nic.getStats().getRealtimeStats().getRxThroughputBytes());

                        JsonArrayBuilder etherTypeJab = Json.createArrayBuilder();
                        for (EthernetTypeStatsEntry etse : nic.getStats().getRxEthernetTypeStats()) {
                            JsonObjectBuilder etherTypeJob = Json.createObjectBuilder();
                            etherTypeJob.add("Code", DataTypeHelpers.byteArrayToHexString(etse.getEthernetType().getCode()));
                            etherTypeJob.add("Name", etse.getEthernetType().toString());
                            etherTypeJob.add("PacketCount", etse.getPacketCount());
                            etherTypeJob.add("ByteCount", etse.getByteCount());
                            etherTypeJab.add(etherTypeJob);
                        }
                        interfaceJob.add("EthernetTypeStats", etherTypeJab);

                        JsonArrayBuilder ipProtoJab = Json.createArrayBuilder();
                        for (IpProtocolStatsEntry ipse : nic.getStats().getRxIpProtocolStats()) {
                            JsonObjectBuilder ipProtoJob = Json.createObjectBuilder();
                            ipProtoJob.add("Code", DataTypeHelpers.byteArrayToHexString(new byte[]{ipse.getIpProtocol().getCode()}));
                            ipProtoJob.add("Name", ipse.getIpProtocol().toString());
                            ipProtoJob.add("PacketCount", ipse.getPacketCount());
                            ipProtoJob.add("ByteCount", ipse.getByteCount());
                            ipProtoJab.add(ipProtoJob);
                        }
                        interfaceJob.add("IpProtocolStats", ipProtoJab);

                        JsonArrayBuilder srcVirtPortJab = Json.createArrayBuilder();
                        for (VirtualPortStatsEntry vpse : nic.getStats().getRxSourceVirtualPortStats()) {
                            JsonObjectBuilder vpseJob = Json.createObjectBuilder();
                            vpseJob.add("PortNumber", vpse.getPortNumber());
                            vpseJob.add("PacketCount", vpse.getPacketCount());
                            vpseJob.add("ByteCount", vpse.getByteCount());
                            srcVirtPortJab.add(vpseJob);
                        }
                        interfaceJob.add("SourceVirtualPortStats", srcVirtPortJab);

                        JsonArrayBuilder dstVirtPortJab = Json.createArrayBuilder();
                        for (VirtualPortStatsEntry vpse : nic.getStats().getRxDestinationVirtualPortStats()) {
                            JsonObjectBuilder vpseJob = Json.createObjectBuilder();
                            vpseJob.add("PortNumber", vpse.getPortNumber());
                            vpseJob.add("PacketCount", vpse.getPacketCount());
                            vpseJob.add("ByteCount", vpse.getByteCount());
                            dstVirtPortJab.add(vpseJob);
                        }
                        interfaceJob.add("DestinationVirtualPortStats", dstVirtPortJab);
                    }
                    interfaceJab.add(interfaceJob);
                }
                responseJob.add("Status", true);
                responseJob.add("InterfaceList", interfaceJab);
                break;
            }
            case "switch.interface-stats-reset": {
                for (NetworkInterface nic : this.switchController.getInterfaceList()) {
                    if (nic.isActive()) {
                        nic.getStats().reset();
                    }
                }
                responseJob.add("Status", true);
                break;
            }
            case "switch.forwarding-table-stats-reset": {
                for (Map.Entry<MacAddress, MacTableEntry> mtee : this.switchController.getForwarder().getMacTable().entrySet()) {
                    MacTableEntry mte = mtee.getValue();
                    mte.resetStats();
                }
                responseJob.add("Status", true);
                break;
            }
            case "switch.forwarding-table-flush": {
                for (Map.Entry<MacAddress, MacTableEntry> mtee : this.switchController.getForwarder().getMacTable().entrySet()) {
                    this.switchController.getForwarder().removeMacTableEntry(mtee.getKey());
                }
                responseJob.add("Status", true);
                break;
            }
            case "switch.forwarding-table-get": {
                JsonArrayBuilder entryJab = Json.createArrayBuilder();
                for (Map.Entry<MacAddress, MacTableEntry> mtee : this.switchController.getForwarder().getMacTable().entrySet()) {
                    MacTableEntry mte = mtee.getValue();
                    JsonObjectBuilder entryJob = Json.createObjectBuilder();
                    entryJob.add("MacAddress", mte.getMacAddress().toString());
                    entryJob.add("InterfaceName", mte.getNetworkInterface().getPcapInterface().getName());
                    entryJob.add("LastSeenTimestamp", mte.getLastSeenDate().getTime());
                    entryJob.add("TxPacketCount", mte.getTxPackets());
                    entryJob.add("TxByteCount", mte.getTxBytes());
                    entryJob.add("RxPacketCount", mte.getRxPackets());
                    entryJob.add("RxByteCount", mte.getRxBytes());
                    entryJab.add(entryJob);
                }
                responseJob.add("Status", true);
                responseJob.add("ForwardingTableEntryList", entryJab);
                break;
            }
            case "netflow.stats-get": {
                if (this.switchController.getFlowExporter() != null) {
                    JsonObjectBuilder netflowStatsJob = Json.createObjectBuilder();
                    netflowStatsJob.add("PacketsProcessed", this.switchController.getFlowExporter().getTotalPacketsProcessed());
                    netflowStatsJob.add("PacketsDiscarded", this.switchController.getFlowExporter().getTotalPacketsDiscarded());
                    netflowStatsJob.add("FlowsSeen", this.switchController.getFlowExporter().getTotalFlowsSeen());
                    netflowStatsJob.add("FlowsExpired", this.switchController.getFlowExporter().getTotalFlowsExpired());
                    netflowStatsJob.add("NetFlowMessagesSent", this.switchController.getFlowExporter().getTotalNetflowMessagesSent());
                    netflowStatsJob.add("StartDate", this.switchController.getFlowExporter().getStartupDate().getTime());
                    responseJob.add("NetFlowStats", netflowStatsJob);
                    responseJob.add("Status", true);
                } else {
                    responseJob.add("Status", false);
                    responseJob.add("Error", "The flow exporter is not running.");
                }

                break;
            }

            case "netflow.config-get": {
                JsonObjectBuilder netflowConfigJob = Json.createObjectBuilder();
                netflowConfigJob.add("Enabled", (this.switchController.getConfig().getProperty("netflow.export.enabled", "false").equals("true")));
                netflowConfigJob.add("DestinationHost", this.switchController.getConfig().getProperty("netflow.destination.host", "127.0.0.1"));
                netflowConfigJob.add("DestinationPort", Integer.parseInt(this.switchController.getConfig().getProperty("netflow.destination.port", "9995")));
                netflowConfigJob.add("FlowTimeout", Integer.parseInt(this.switchController.getConfig().getProperty("netflow.flow.timeout", "60000")));
                netflowConfigJob.add("ExportInterval", Integer.parseInt(this.switchController.getConfig().getProperty("netflow.export.interval", "100")));
                responseJob.add("NetflowConfiguration", netflowConfigJob);
                responseJob.add("Status", true);
                break;
            }

            case "netflow.config-set": {
                boolean iEnabled = request.getParameter("enabled") != null && request.getParameter("enabled").equals("true");
                String iDestinationHost = request.getParameter("destination-host");
                Integer iDestinationPort = Integer.parseInt(request.getParameter("destination-port"));
                Integer iFlowTimeout = Integer.parseInt(request.getParameter("flow-timeout"));
                Integer iExportInterval = Integer.parseInt(request.getParameter("export-interval"));

                this.switchController.getConfig().setProperty("netflow.export.enabled", (iEnabled) ? "true" : "false");
                this.switchController.getConfig().setProperty("netflow.destination.host", iDestinationHost);
                this.switchController.getConfig().setProperty("netflow.destination.port", Integer.toString(iDestinationPort));
                this.switchController.getConfig().setProperty("netflow.flow.timeout", Integer.toString(iFlowTimeout));
                this.switchController.getConfig().setProperty("netflow.export.interval", Integer.toString(iExportInterval));
                this.switchController.writeConfiguration();

                if (this.switchController.getFlowExporter() != null && iEnabled) {
                    this.switchController.getFlowExporter().setNfDestinationAddress(IpAddress.fromString(iDestinationHost));
                    this.switchController.getFlowExporter().setNfDestinationPort(iDestinationPort);
                    this.switchController.getFlowExporter().setFlowTimeout(iFlowTimeout);
                    this.switchController.getFlowExporter().setExportInterval(iExportInterval);
                } else if (this.switchController.getFlowExporter() != null && !iEnabled) {
                    this.switchController.stopFlowExporter();
                } else if (this.switchController.getFlowExporter() == null && iEnabled) {
                    this.switchController.startFlowExporter();
                }
                responseJob.add("Status", true);
                break;
            }
            default: {
                responseJob.add("Status", false);
                responseJob.add("Error", "invalid api request (" + apiCallName + ")");
            }
        }
        response.setStatus(HttpServletResponse.SC_OK);

        Map<String, Object> jwConfig = new HashMap<String, Object>();

        jwConfig.put(JsonGenerator.PRETTY_PRINTING,
                true);
        JsonWriter jw = Json.createWriterFactory(jwConfig).createWriter(response.getOutputStream());

        jw.writeObject(responseJob.build());
    }

    private void insertToJsonObject(JsonObjectBuilder job, String n, Object o) {
        if (o == null) {
            job.addNull(n);
        } else if (o instanceof Integer) {
            job.add(n, (Integer) o);
        } else {
            job.add(n, o.toString());
        }
    }
}
