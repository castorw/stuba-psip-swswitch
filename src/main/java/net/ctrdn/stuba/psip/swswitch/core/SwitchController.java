package net.ctrdn.stuba.psip.swswitch.core;

import net.ctrdn.stuba.psip.swswitch.common.IpAddress;
import net.ctrdn.stuba.psip.swswitch.common.MacAddress;
import net.ctrdn.stuba.psip.swswitch.nic.NetworkInterface;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import net.ctrdn.stuba.psip.swswitch.acl.AccessList;
import net.ctrdn.stuba.psip.swswitch.acl.AccessListAction;
import net.ctrdn.stuba.psip.swswitch.acl.AccessListEntry;
import net.ctrdn.stuba.psip.swswitch.acl.AccessListImpl;
import net.ctrdn.stuba.psip.swswitch.common.EthernetType;
import net.ctrdn.stuba.psip.swswitch.common.IpProtocol;
import net.ctrdn.stuba.psip.swswitch.common.DataTypeHelpers;
import net.ctrdn.stuba.psip.swswitch.adminportal.ApiServlet;
import net.ctrdn.stuba.psip.swswitch.adminportal.ResourceServlet;
import net.ctrdn.stuba.psip.swswitch.netflow.FlowExporter;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

final public class SwitchController implements Runnable {

    private final File configFile = new File("stuba-psip-swswitch.properties");
    private Properties config;
    private final Logger logger = LoggerFactory.getLogger(SwitchController.class);
    private final List<NetworkInterface> interfaceList = new ArrayList<>();
    private final List<AccessList> aclList = new ArrayList<>();
    private final Queue<IncomingFrame> incomingFrameQueue = new ConcurrentLinkedQueue<>();
    private final Object incomingFrameLock = new Object();
    private Forwarder forwarder;
    private Thread forwarderThread;
    private FlowExporter flowExporter = null;
    private Thread flowExporterThread;

    public SwitchController() {
    }

    public void reloadConfiguration() {
        try {
            if (!configFile.exists()) {
                configFile.createNewFile();
            }
            this.logger.info("Reloading configuration from " + configFile.getAbsolutePath());
            this.config = new Properties();
            this.config.load(new FileInputStream(configFile));
        } catch (IOException ex) {
            this.logger.error("Failed to load configuration", ex);
        }
    }

    public void writeConfiguration() {
        try {
            this.logger.warn("Writing configuration to " + configFile.getAbsolutePath());

            for (String paramName : this.config.stringPropertyNames()) {
                if (paramName.startsWith("acl.")) {
                    this.config.remove(paramName);
                }
            }

            for (AccessList acl : this.aclList) {
                Map<String, String> aclConfig = acl.getConfigurationEntries();
                for (Map.Entry<String, String> entry : aclConfig.entrySet()) {
                    this.config.setProperty(entry.getKey(), (entry.getValue() == null) ? "" : entry.getValue());
                }
            }

            try (FileOutputStream fos = new FileOutputStream(configFile)) {
                this.config.store(fos, "");
            }
        } catch (IOException ex) {
            this.logger.error("Failed to load configuration", ex);
        }
    }

    public void initialize() {
        this.reloadConfiguration();
        this.enumerateInterfaces();
        this.loadAccessLists();
        this.startSwitchports();
        this.startForwarder();
        this.startFlowExporter();
        this.writeConfiguration();
        this.startWebserver();
    }

    private void enumerateInterfaces() {
        List<PcapIf> list = new ArrayList<>();
        StringBuilder errorBuffer = new StringBuilder();
        Pcap.findAllDevs(list, errorBuffer);
        for (PcapIf iface : list) {
            String ifname = iface.getName();
            String enabled = this.config.getProperty("interface." + ifname + ".switchport.enabled");
            if (enabled == null) {
                this.config.setProperty("interface." + ifname + ".switchport.enabled", "false");
            }
            this.getInterfaceList().add(new NetworkInterface(iface));
        }
        Collections.sort(this.interfaceList, new Comparator<NetworkInterface>() {

            @Override
            public int compare(NetworkInterface o1, NetworkInterface o2) {
                return o1.getPcapInterface().getName().compareTo(o2.getPcapInterface().getName());
            }
        });
    }

    public void reloadAccessLists() {
        this.loadAccessLists();
    }

    private void loadAccessLists() {
        this.aclList.clear();
        List<String> aclIdStringlist = new ArrayList<>();
        for (String line : this.config.stringPropertyNames()) {
            if (line.startsWith("acl.")) {
                String[] aclSplit = line.split("\\.");
                if (!aclIdStringlist.contains(aclSplit[1])) {
                    aclIdStringlist.add(aclSplit[1]);
                }
            }
        }
        for (String aclIdString : aclIdStringlist) {
            byte[] aclId = DataTypeHelpers.hexStringToByteArray(aclIdString);
            String aclName = this.config.getProperty("acl." + aclIdString + ".name");
            AccessList acl = new AccessListImpl(aclId, (aclName.trim().isEmpty()) ? null : aclName);

            List<String> entryIdStingList = new ArrayList<>();
            String aclEntryPrefix = "acl." + aclIdString + ".entry.";
            for (String line : this.config.stringPropertyNames()) {
                if (line.startsWith(aclEntryPrefix)) {
                    String[] split = line.split("\\.");
                    if (!entryIdStingList.contains(split[3])) {
                        entryIdStingList.add(split[3]);
                    }
                }
            }
            for (String entryIdString : entryIdStingList) {
                int entryId = Integer.parseInt(entryIdString);
                String entryPrefix = aclEntryPrefix + entryIdString;
                AccessListEntry entry = new AccessListEntry(acl, entryId);
                entry.setAction(AccessListAction.valueOf(this.config.getProperty(entryPrefix + ".action")));
                String cSrcMac = this.config.getProperty(entryPrefix + ".src-mac");
                String cDstMac = this.config.getProperty(entryPrefix + ".dst-mac");
                String cEtherType = this.config.getProperty(entryPrefix + ".ether-type");
                String cSrcIp = this.config.getProperty(entryPrefix + ".src-ip");
                String cDstIp = this.config.getProperty(entryPrefix + ".dst-ip");
                String cIpProto = this.config.getProperty(entryPrefix + ".ip-type");
                String cSrcPort = this.config.getProperty(entryPrefix + ".src-port");
                String cDstPort = this.config.getProperty(entryPrefix + ".dst-port");
                String cOrderKey = this.config.getProperty(entryPrefix + ".order-key");

                entry.setSourceMacAddress((cSrcMac.trim().equals("*")) ? null : MacAddress.fromString(cSrcMac));
                entry.setDestinationMacAddress((cDstMac.trim().equals("*")) ? null : MacAddress.fromString(cDstMac));
                entry.setEthernetType((cEtherType.trim().equals("*") ? null : EthernetType.valueOf(cEtherType)));
                entry.setSourceIpAddress(((cSrcIp.trim().equals("*") ? null : IpAddress.fromString(cSrcIp))));
                entry.setDestinationIpAddress(((cDstIp.trim().equals("*") ? null : IpAddress.fromString(cDstIp))));
                entry.setIpProtocol(((cIpProto.trim().equals("*") ? null : IpProtocol.valueOf(cIpProto))));
                entry.setTcpUdpSourcePort(((cSrcPort.trim().equals("*") ? null : Integer.parseInt(cSrcPort))));
                entry.setTcpUdpDestinationPort(((cDstPort.trim().equals("*") ? null : Integer.parseInt(cDstPort))));
                entry.setOrderKey(Integer.parseInt(cOrderKey));

                acl.add(entry);
            }
            acl.sort();

            this.aclList.add(acl);
        }
        Collections.sort(this.aclList, new Comparator<AccessList>() {

            @Override
            public int compare(AccessList o1, AccessList o2) {
                if (o1.getName() == null && o2.getName() == null) {
                    return 0;
                } else if (o1.getName() == null && o2.getName() != null) {
                    return 1;
                } else if (o1.getName() != null && o2.getName() == null) {
                    return -1;
                } else {
                    return o1.getName().compareTo(o2.getName());
                }
            }
        });

        for (NetworkInterface nic : this.interfaceList) {
            String ingressAclIdString = this.config.getProperty("interface." + nic.getPcapInterface().getName() + ".acl.ingress");
            String egressAclIdString = this.config.getProperty("interface." + nic.getPcapInterface().getName() + ".acl.egress");
            if (ingressAclIdString != null && !ingressAclIdString.trim().isEmpty()) {
                AccessList ingressAcl = this.getAclById(DataTypeHelpers.hexStringToByteArray(ingressAclIdString));
                nic.setIngressAccessList(ingressAcl);
            }
            if (egressAclIdString != null && !egressAclIdString.trim().isEmpty()) {
                AccessList egressAcl = this.getAclById(DataTypeHelpers.hexStringToByteArray(egressAclIdString));
                nic.setEgressAccessList(egressAcl);
            }
        }
    }

    private void startSwitchports() {
        for (NetworkInterface nic : this.interfaceList) {
            String enabled = this.config.getProperty("interface." + nic.getPcapInterface().getName() + ".switchport.enabled", "false");
            if (enabled.equals("true")) {
                nic.startSwitchport(this);
            }
        }
    }

    private void startForwarder() {
        this.forwarder = new Forwarder(this);
        this.forwarderThread = new Thread(this.getForwarder());
        this.forwarderThread.start();
    }

    public void startFlowExporter() {
        if (this.config.getProperty("netflow.export.enabled") != null && this.config.getProperty("netflow.export.enabled").equals("true")) {
            IpAddress destinationAddress = IpAddress.fromString(this.config.getProperty("netflow.destination.host"));
            int destinationPort = Integer.parseInt(this.config.getProperty("netflow.destination.port"));
            int exportInterval = Integer.parseInt(this.config.getProperty("netflow.export.interval"));
            int flowTimeout = Integer.parseInt(this.config.getProperty("netflow.flow.timeout"));
            this.flowExporter = new FlowExporter(this, destinationAddress, destinationPort, flowTimeout, exportInterval);
            this.flowExporterThread = new Thread(this.getFlowExporter());
            this.flowExporterThread.start();
        } else {
            this.logger.info("Flow exporter will not start because it is disabled in configuration");
        }
    }

    public void stopFlowExporter() {
        if (this.getFlowExporter() != null && this.flowExporterThread != null) {
            this.getFlowExporter().stop();
            this.flowExporter = null;
            this.flowExporterThread = null;
        }
    }

    private void startWebserver() {
        try {
            ServletContextHandler sch = new ServletContextHandler(ServletContextHandler.SESSIONS);
            sch.setContextPath("/");
            sch.addServlet(new ServletHolder(new ApiServlet(this)), "/api/*");
            sch.addServlet(new ServletHolder(new ResourceServlet()), "/*");

            Server server = new Server(Integer.parseInt(this.config.getProperty("webserver.http.port", "80")));
            server.setHandler(sch);
            server.start();
            server.join();
        } catch (Exception ex) {
            this.logger.error("Webserver error", ex);
        }
    }

    @Override
    public void run() {
        this.logger.debug("Switch controller is starting up");
    }

    public List<NetworkInterface> getInterfaceList() {
        return interfaceList;
    }

    public Queue<IncomingFrame> getIncomingFrameQueue() {
        return incomingFrameQueue;
    }

    public void offerIncomingFrame(IncomingFrame iframe) {
        synchronized (this.getIncomingFrameLock()) {
            this.incomingFrameQueue.offer(iframe);
            this.getIncomingFrameLock().notifyAll();
        }
    }

    public Properties getConfig() {
        return config;
    }

    public Object getIncomingFrameLock() {
        return incomingFrameLock;
    }

    public Forwarder getForwarder() {
        return forwarder;
    }

    public List<AccessList> getAccessLists() {
        return aclList;
    }

    public AccessList getAclById(byte[] id) {
        for (AccessList acl : this.aclList) {
            if (Arrays.equals(acl.getId(), id)) {
                return acl;
            }
        }
        return null;
    }

    public byte[] getVirtualNetworkInterfaceSnmpIndex(NetworkInterface nic) {
        if (this.interfaceList.contains(nic)) {
            int index = this.interfaceList.indexOf(nic);
            byte[] ifIndex = new byte[2];
            ifIndex[0] = 0;
            ifIndex[1] = (byte) (index & 0xff);
            return ifIndex;
        } else {
            throw new RuntimeException("Attempted to get SNMP index for non-existent device.");
        }
    }

    public FlowExporter getFlowExporter() {
        return flowExporter;
    }
}
