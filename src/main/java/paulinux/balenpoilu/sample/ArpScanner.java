package paulinux.balenpoilu.sample;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.ptr.IntByReference;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;

/**
 * Scanner ARP, mDNS/Bonjour et Ports pour le réseau local.
 *
 * Fonctionnalités :
 * - Découverte ARP native sans pilote Npcap (Windows SendARP via iphlpapi.dll).
 * - Résolution des noms via mDNS (Multicast DNS / Bonjour), LLMNR et NetBIOS.
 * - Identification automatique du fabricant via les préfixes MAC OUI.
 * - Scan asynchrone des ports TCP ouverts avec identification des services (Virtual Threads).
 */
public class ArpScanner {

    public interface IpHlpApi extends Library {
        IpHlpApi INSTANCE = Native.load("iphlpapi", IpHlpApi.class);
        int SendARP(int destIP, int srcIP, byte[] pMacAddr, IntByReference phyAddrLen);
    }

    private static final boolean IS_WINDOWS = System.getProperty("os.name", "").toLowerCase().contains("win");

    /**
     * Dictionnaire des ports bien connus et services associés.
     */
    private static final Map<Integer, String> WELL_KNOWN_SERVICES = new LinkedHashMap<>();

    static {
        WELL_KNOWN_SERVICES.put(21, "FTP");
        WELL_KNOWN_SERVICES.put(22, "SSH");
        WELL_KNOWN_SERVICES.put(23, "Telnet");
        WELL_KNOWN_SERVICES.put(25, "SMTP");
        WELL_KNOWN_SERVICES.put(53, "DNS");
        WELL_KNOWN_SERVICES.put(80, "HTTP");
        WELL_KNOWN_SERVICES.put(110, "POP3");
        WELL_KNOWN_SERVICES.put(135, "RPC / EPMAP");
        WELL_KNOWN_SERVICES.put(139, "NetBIOS-SSN");
        WELL_KNOWN_SERVICES.put(143, "IMAP");
        WELL_KNOWN_SERVICES.put(443, "HTTPS");
        WELL_KNOWN_SERVICES.put(445, "SMB / Microsoft-DS");
        WELL_KNOWN_SERVICES.put(548, "AFP (Apple Filing)");
        WELL_KNOWN_SERVICES.put(554, "RTSP (Streaming vidéo / Caméra)");
        WELL_KNOWN_SERVICES.put(631, "IPP (Impression CUPS)");
        WELL_KNOWN_SERVICES.put(993, "IMAPS");
        WELL_KNOWN_SERVICES.put(995, "POP3S");
        WELL_KNOWN_SERVICES.put(1433, "Microsoft SQL Server");
        WELL_KNOWN_SERVICES.put(1521, "Oracle DB");
        WELL_KNOWN_SERVICES.put(2049, "NFS");
        WELL_KNOWN_SERVICES.put(3306, "MySQL / MariaDB");
        WELL_KNOWN_SERVICES.put(3389, "RDP (Bureau à distance)");
        WELL_KNOWN_SERVICES.put(5000, "UPnP / Synology DSM");
        WELL_KNOWN_SERVICES.put(5357, "WSDAPI (Windows Discovery)");
        WELL_KNOWN_SERVICES.put(5432, "PostgreSQL");
        WELL_KNOWN_SERVICES.put(5900, "VNC");
        WELL_KNOWN_SERVICES.put(6379, "Redis");
        WELL_KNOWN_SERVICES.put(8000, "HTTP-Alt / Dev Server");
        WELL_KNOWN_SERVICES.put(8080, "HTTP-Proxy / Web Alternate");
        WELL_KNOWN_SERVICES.put(8081, "HTTP-Alt");
        WELL_KNOWN_SERVICES.put(8443, "HTTPS-Alt");
        WELL_KNOWN_SERVICES.put(8888, "HTTP-Alt / Jupyter");
        WELL_KNOWN_SERVICES.put(9000, "Portainer / SonarQube / PHP-FPM");
        WELL_KNOWN_SERVICES.put(9090, "Prometheus / Cockpit");
        WELL_KNOWN_SERVICES.put(32400, "Plex Media Server");
    }

    /**
     * Dictionnaire partiel des préfixes MAC OUI pour identifier le fabricant.
     */
    private static final Map<String, String> MAC_VENDORS = new HashMap<>();

    static {
        MAC_VENDORS.put("58:FC:20", "Sagemcom (Box / Routeur)");
        MAC_VENDORS.put("E4:9E:12", "Sagemcom");
        MAC_VENDORS.put("F8:D1:11", "Sagemcom");
        MAC_VENDORS.put("00:24:D4", "Freebox");
        MAC_VENDORS.put("14:0C:76", "Freebox");
        MAC_VENDORS.put("70:FC:8F", "Freebox");
        MAC_VENDORS.put("74:56:3C", "Realtek");
        MAC_VENDORS.put("00:E0:4C", "Realtek");
        MAC_VENDORS.put("54:EE:75", "Realtek");
        MAC_VENDORS.put("10:68:38", "Intel");
        MAC_VENDORS.put("F4:34:F0", "Intel");
        MAC_VENDORS.put("B8:85:84", "Intel");
        MAC_VENDORS.put("BC:10:2F", "Apple");
        MAC_VENDORS.put("F0:18:98", "Apple");
        MAC_VENDORS.put("AC:BC:32", "Apple");
        MAC_VENDORS.put("F4:F5:D8", "Apple");
        MAC_VENDORS.put("64:57:25", "Espressif (IoT / ESP32)");
        MAC_VENDORS.put("24:62:AB", "Espressif");
        MAC_VENDORS.put("30:AE:A4", "Espressif");
        MAC_VENDORS.put("84:F3:EB", "Espressif");
        MAC_VENDORS.put("CC:8C:BF", "Tuya / Smart Life (IoT)");
        MAC_VENDORS.put("60:35:C0", "Tuya / Smart Life (IoT)");
        MAC_VENDORS.put("1C:79:2D", "Xiaomi / Smart Device");
        MAC_VENDORS.put("3C:0B:59", "Xiaomi");
        MAC_VENDORS.put("B8:27:EB", "Raspberry Pi");
        MAC_VENDORS.put("DC:A6:32", "Raspberry Pi");
        MAC_VENDORS.put("E4:5F:01", "Raspberry Pi");
        MAC_VENDORS.put("00:11:32", "Synology");
        MAC_VENDORS.put("E8:48:B8", "TP-Link");
        MAC_VENDORS.put("50:C7:BF", "TP-Link");
        MAC_VENDORS.put("F6:A3:EB", "Adresse privée (Apple/Android)");
    }

    public record OpenPort(int port, String service) {
        @Override
        public String toString() {
            return port + (service != null ? " (" + service + ")" : "");
        }
    }

    public record DiscoveredDevice(String ip, String mac, String name, String vendor, List<OpenPort> openPorts) {
        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("--------------------------------------------------------------------------------\n");
            sb.append(String.format("  [Appareil] IP: %-15s | Nom: %s\n", ip, (name != null ? name : "Inconnu")));
            sb.append(String.format("             MAC: %-17s | Fabricant: %s\n", mac, (vendor != null ? vendor : "Non répertorié")));
            sb.append("             Ports ouverts : ");
            if (openPorts.isEmpty()) {
                sb.append("Aucun port détecté (ou filtrés par pare-feu)");
            } else {
                sb.append(openPorts.size()).append(" port(s) ouvert(s) -> ");
                for (int i = 0; i < openPorts.size(); i++) {
                    sb.append(openPorts.get(i));
                    if (i < openPorts.size() - 1) sb.append(", ");
                }
            }
            return sb.toString();
        }
    }

    public static int inetAddressToLittleEndianInt(InetAddress ip) {
        byte[] bytes = ip.getAddress();
        return (bytes[0] & 0xFF)
                | ((bytes[1] & 0xFF) << 8)
                | ((bytes[2] & 0xFF) << 16)
                | ((bytes[3] & 0xFF) << 24);
    }

    public static String formatMac(byte[] mac, int len) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len; i++) {
            sb.append(String.format("%02X", mac[i]));
            if (i < len - 1) {
                sb.append(":");
            }
        }
        return sb.toString();
    }

    public static String lookupMacVendor(String mac) {
        if (mac == null || mac.length() < 8) return null;
        String prefix = mac.substring(0, 8).toUpperCase();
        return MAC_VENDORS.get(prefix);
    }

    /**
     * Résout les noms d'hôtes via mDNS (Bonjour / Multicast DNS) et LLMNR.
     */
    public static Map<String, String> resolveMdnsHostNames(Collection<String> ips) {
        Map<String, String> results = new ConcurrentHashMap<>();
        if (ips == null || ips.isEmpty()) return results;

        if (IS_WINDOWS) {
            try {
                StringBuilder sb = new StringBuilder();
                sb.append("& { ");
                for (String ip : ips) {
                    sb.append("'").append(ip).append("',");
                }
                if (sb.charAt(sb.length() - 1) == ',') {
                    sb.deleteCharAt(sb.length() - 1);
                }
                sb.append(" | ForEach-Object { $r = Resolve-DnsName $_ -ErrorAction SilentlyContinue; if ($r.NameHost) { Write-Output ($_ + '|' + $r.NameHost) } } }");

                Process process = new ProcessBuilder("powershell", "-NoProfile", "-NonInteractive", "-Command", sb.toString()).start();
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        line = line.trim();
                        if (line.contains("|")) {
                            String[] parts = line.split("\\|", 2);
                            String ip = parts[0].trim();
                            String name = parts[1].trim().replace("{", "").replace("}", "").split("\\s+")[0];
                            if (!name.isBlank() && !name.equalsIgnoreCase(ip)) {
                                results.put(ip, name);
                            }
                        }
                    }
                }
                process.waitFor(10, TimeUnit.SECONDS);
            } catch (Exception ignored) {
            }
        }

        for (String ip : ips) {
            if (!results.containsKey(ip)) {
                String netbios = queryNetBiosName(ip);
                if (netbios != null && !netbios.isBlank()) {
                    results.put(ip, netbios);
                } else {
                    try {
                        InetAddress addr = InetAddress.getByName(ip);
                        String host = addr.getCanonicalHostName();
                        if (host != null && !host.equalsIgnoreCase(ip)) {
                            results.put(ip, host);
                        }
                    } catch (Exception ignored) {
                    }
                }
            }
        }

        return results;
    }

    /**
     * Résout le nom NetBIOS d'une machine via une requête UDP sur le port 137.
     */
    public static String queryNetBiosName(String ip) {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(350);
            byte[] request = new byte[] {
                    (byte) 0x82, 0x28, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41,
                    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                    0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21, 0x00, 0x01
            };
            InetAddress address = InetAddress.getByName(ip);
            DatagramPacket packet = new DatagramPacket(request, request.length, address, 137);
            socket.send(packet);

            byte[] buffer = new byte[1024];
            DatagramPacket response = new DatagramPacket(buffer, buffer.length);
            socket.receive(response);

            if (response.getLength() > 57) {
                int numNames = buffer[56] & 0xFF;
                if (numNames > 0 && response.getLength() >= 57 + 15) {
                    String name = new String(buffer, 57, 15, StandardCharsets.US_ASCII).trim();
                    if (!name.isEmpty() && !name.contains("\u0000")) {
                        return name;
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    /**
     * Teste si un port TCP est ouvert sur une adresse IP donnée.
     */
    public static OpenPort checkPort(String ip, int port, int timeoutMs) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(ip, port), timeoutMs);
            String service = WELL_KNOWN_SERVICES.getOrDefault(port, "Service TCP");
            return new OpenPort(port, service);
        } catch (IOException ignored) {
            return null;
        }
    }

    /**
     * Scanne une liste de ports sur un hôte donné à l'aide de Virtual Threads.
     */
    public static List<OpenPort> scanPortsForHost(String ip, Set<Integer> portsToScan, int timeoutMs) {
        List<OpenPort> openPorts = new CopyOnWriteArrayList<>();

        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Callable<Void>> tasks = new ArrayList<>();
            for (int port : portsToScan) {
                tasks.add(() -> {
                    OpenPort result = checkPort(ip, port, timeoutMs);
                    if (result != null) {
                        openPorts.add(result);
                    }
                    return null;
                });
            }
            executor.invokeAll(tasks);
        } catch (InterruptedException ignored) {
        }

        openPorts.sort(Comparator.comparingInt(OpenPort::port));
        return openPorts;
    }

    public static NetworkInterface findActiveLanInterface() throws SocketException {
        Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
        NetworkInterface candidate = null;

        while (interfaces.hasMoreElements()) {
            NetworkInterface netIf = interfaces.nextElement();
            if (!netIf.isUp() || netIf.isLoopback() || netIf.isVirtual()) {
                continue;
            }

            for (InterfaceAddress ifAddr : netIf.getInterfaceAddresses()) {
                InetAddress addr = ifAddr.getAddress();
                if (addr instanceof Inet4Address ip && !ip.isLoopbackAddress()) {
                    if (ip.getHostAddress().startsWith("192.168.")) {
                        return netIf;
                    }
                    if (ip.isSiteLocalAddress() && candidate == null) {
                        candidate = netIf;
                    }
                }
            }
        }
        return candidate;
    }

    public static String queryMacWindows(InetAddress ip) {
        byte[] macBytes = new byte[6];
        IntByReference macLen = new IntByReference(6);
        int destInt = inetAddressToLittleEndianInt(ip);

        int status = IpHlpApi.INSTANCE.SendARP(destInt, 0, macBytes, macLen);
        if (status == 0 && macLen.getValue() == 6) {
            return formatMac(macBytes, 6);
        }
        return null;
    }

    public static Map<String, String> discoverHosts(String subnetPrefix) throws InterruptedException {
        Map<String, String> discovered = new ConcurrentHashMap<>();

        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Callable<Void>> tasks = new ArrayList<>();

            for (int i = 1; i <= 254; i++) {
                final String targetIpStr = subnetPrefix + i;
                tasks.add(() -> {
                    try {
                        InetAddress targetIp = InetAddress.getByName(targetIpStr);
                        if (IS_WINDOWS) {
                            String mac = queryMacWindows(targetIp);
                            if (mac != null) {
                                discovered.put(targetIpStr, mac);
                                System.out.println("  [+] Appareil détecté : " + targetIpStr + " (" + mac + ")");
                            }
                        } else {
                            if (targetIp.isReachable(300)) {
                                discovered.put(targetIpStr, "Inconnue");
                            }
                        }
                    } catch (Exception ignored) {
                    }
                    return null;
                });
            }

            executor.invokeAll(tasks);
        }

        return discovered;
    }

    public static void main(String[] args) {
        System.out.println("================================================================================");
        System.out.println("     SCANNER COMPLET DU RESEAU LOCAL (ARP + mDNS/Bonjour + PORTS OUVERTS)       ");
        System.out.println("================================================================================");

        try {
            NetworkInterface netIf = findActiveLanInterface();
            if (netIf == null) {
                System.err.println("Aucune interface réseau active trouvée.");
                return;
            }

            Inet4Address localIp = null;
            for (InterfaceAddress ifAddr : netIf.getInterfaceAddresses()) {
                if (ifAddr.getAddress() instanceof Inet4Address ip && !ip.isLoopbackAddress()) {
                    localIp = ip;
                    break;
                }
            }

            if (localIp == null) {
                System.err.println("Impossible de déterminer l'adresse IPv4 locale.");
                return;
            }

            byte[] hw = netIf.getHardwareAddress();
            String localMac = (hw != null) ? formatMac(hw, hw.length) : "Inconnue";
            String ipStr = localIp.getHostAddress();
            String subnetPrefix = ipStr.substring(0, ipStr.lastIndexOf('.') + 1);

            System.out.println("Interface détectée : " + netIf.getDisplayName());
            System.out.println("IP locale          : " + ipStr + " | MAC : " + localMac);
            System.out.println("Plage de scan      : " + subnetPrefix + "1 -> " + subnetPrefix + "254");
            System.out.println("--------------------------------------------------------------------------------");
            System.out.println("[ETAPE 1/3] Recherche des appareils actifs (ARP Scan)...");

            long start = System.currentTimeMillis();
            Map<String, String> activeHosts = discoverHosts(subnetPrefix);

            System.out.println("\n-> " + activeHosts.size() + " appareil(s) actif(s) identifié(s).");
            System.out.println("--------------------------------------------------------------------------------");
            System.out.println("[ETAPE 2/3] Résolution des noms via mDNS / Bonjour / LLMNR / NetBIOS...");

            Map<String, String> resolvedNames = resolveMdnsHostNames(activeHosts.keySet());
            System.out.println("-> Noms résolus : " + resolvedNames.size() + " appareil(s) nommé(s).");

            System.out.println("--------------------------------------------------------------------------------");
            System.out.println("[ETAPE 3/3] Scan des ports TCP ouverts (Virtual Threads)...");

            Set<Integer> portsToScan = new TreeSet<>();
            for (int p = 1; p <= 1024; p++) {
                portsToScan.add(p);
            }
            portsToScan.addAll(WELL_KNOWN_SERVICES.keySet());

            List<DiscoveredDevice> devices = new CopyOnWriteArrayList<>();

            try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
                List<Callable<Void>> tasks = new ArrayList<>();

                for (Map.Entry<String, String> entry : activeHosts.entrySet()) {
                    final String ip = entry.getKey();
                    final String mac = entry.getValue();

                    tasks.add(() -> {
                        String vendor = lookupMacVendor(mac);
                        String name = resolvedNames.get(ip);
                        if (name == null || name.isBlank()) {
                            name = (vendor != null ? "Appareil " + vendor : "Inconnu");
                        }

                        List<OpenPort> openPorts = scanPortsForHost(ip, portsToScan, 200);
                        DiscoveredDevice device = new DiscoveredDevice(ip, mac, name, vendor, openPorts);
                        devices.add(device);
                        return null;
                    });
                }

                executor.invokeAll(tasks);
            }

            devices.sort(Comparator.comparingInt(d -> {
                String[] parts = d.ip().split("\\.");
                return Integer.parseInt(parts[3]);
            }));

            long duration = System.currentTimeMillis() - start;

            System.out.println("\n================================================================================");
            System.out.println("                          RESULTATS DU SCAN DU RESEAU                           ");
            System.out.println("================================================================================");

            for (DiscoveredDevice dev : devices) {
                System.out.println(dev);
            }

            System.out.println("--------------------------------------------------------------------------------");
            System.out.println("Scan global terminé avec succès en " + (duration / 1000.0) + " secondes.");
            System.out.println("Total : " + devices.size() + " appareil(s) analysé(s).");
            System.out.println("================================================================================");

        } catch (Exception e) {
            System.err.println("Erreur lors de l'exécution : " + e.getMessage());
            e.printStackTrace();
        }
    }
}