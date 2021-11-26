/*
Copyright 2009-2021 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

using System;
using System.IO;
using System.Collections;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.ServiceProcess;
using System.Web.Script.Serialization;
using System.Net;
using System.Configuration.Install;
using System.Reflection;

namespace MeshCentralRouterCmd
{
    class Program
    {
        static bool debug = false;
        //static bool tlsdump = false;
        static bool ignoreCert = false;
        static bool inaddrany = false;
        static MeshCentralServer meshcentral;
        static string url = null;
        static string username = null;
        static string password = null;
        static string token = null;
        static string serverid = null;
        static string serverTlsHash = null;
        static MeshDiscovery discovery = null;
        static List<MeshMapper> mappers = new List<MeshMapper>();
        static List<PortMap> PortMaps = null;
        static bool runAsService = false;
        static string executablePath = null;

        public class PortMap
        {
            public string name = null;
            public string nodeName = null;
            public int protocol = 1; // 1 = TCP, 2 = UDP
            public int localPort = 0; // 0 = Any
            public int remotePort = 0;
            public string remoteIP = null;
            public string remoteNodeId = null;
        }

        static public void Log(string msg)
        {
            Console.WriteLine(msg);
            //try { File.AppendAllText(Path.Combine(executablePath, "debug.log"), DateTime.Now.ToString("HH:mm:tt.ffff") + ": MCAgent: " + msg + "\r\n"); } catch (Exception) { }
        }

        //[STAThread]
        static void Main(string[] args)
        {
            // Get our assembly path
            FileInfo fi = new FileInfo(Path.Combine(Assembly.GetExecutingAssembly().Location));
            executablePath = fi.Directory.FullName;

            Log("MeshCentral Router Command Line Tool.");

            // Parse the meshaction.txt file
            string action = null;
            try { action = File.ReadAllText("meshaction.txt"); } catch (Exception) { }
            if (action == null) { try { action = File.ReadAllText(Path.Combine(executablePath, "meshaction.txt")); } catch (Exception) { } }
            PortMap defaultPortMap = new PortMap();
            if (action != null)
            {
                Dictionary<string, object> jsonAction = new Dictionary<string, object>();
                jsonAction = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(action);
                foreach (string key in jsonAction.Keys)
                {
                    string keyl = key.ToLower();
                    if (keyl == "username") { username = (string)jsonAction[key]; }
                    if (keyl == "password") { password = (string)jsonAction[key]; }
                    if (keyl == "token") { token = (string)jsonAction[key]; }
                    if (keyl == "debuglevel") { debug = ((int)jsonAction[key]) > 0; }
                    if (keyl == "serverurl") { url = (string)jsonAction[key]; }
                    if (keyl == "hostname") { url = "wss://" + (string)jsonAction[key] + "/meshrelay.ashx"; }
                    if (keyl == "serverid") { serverid = (string)jsonAction[key]; }
                    if (keyl == "serverhttpshash") { serverTlsHash = (string)jsonAction[key]; }
                    if (keyl == "certhash") { serverTlsHash = (string)jsonAction[key]; }
                    if (keyl == "remotetarget") { defaultPortMap.remoteIP = (string)jsonAction[key]; }
                    if (keyl == "remoteport") { defaultPortMap.remotePort = (int)jsonAction[key]; }
                    if (keyl == "localport") { defaultPortMap.localPort = (int)jsonAction[key]; }
                    if (keyl == "remotenodeid") { defaultPortMap.remoteNodeId = (string)jsonAction[key]; }
                    if (keyl == "mappings") {
                        PortMaps = new List<PortMap>();
                        ArrayList xmappings = (ArrayList)jsonAction[key];
                        foreach (Dictionary<string, object> xmap in xmappings)
                        {
                            PortMap addedPortMap = new PortMap();
                            foreach (string xkey in xmap.Keys)
                            {
                                string xkeyl = xkey.ToLower();
                                if (xkeyl == "name") { addedPortMap.name = (string)xmap[xkey]; }
                                if (xkeyl == "nodename") { addedPortMap.nodeName = (string)xmap[xkey]; }
                                if (xkeyl == "remoteip") { addedPortMap.remoteIP = (string)xmap[xkey]; }
                                if (xkeyl == "remoteport") { addedPortMap.remotePort = (int)xmap[xkey]; }
                                if (xkeyl == "localport") { addedPortMap.localPort = (int)xmap[xkey]; }
                                if (xkeyl == "nodeid") { addedPortMap.remoteNodeId = (string)xmap[xkey]; }
                            }
                            PortMaps.Add(addedPortMap);
                        }
                    }
                }
            }

            // Use the default port map if a list is not specified
            if (PortMaps == null)
            {
                PortMaps = new List<PortMap>();
                PortMaps.Add(defaultPortMap);
            }

            // Parse arguments
            bool help = false;
            for (int i = 0; i < args.Length; i++)
            {
                string arg = args[i].ToLower();
                if (arg == "--help") { help = true; }
                if (arg == "--debug") { debug = true; }
                //if (arg == "--tlsdump") { tlsdump = true; }
                if (arg == "--ignorecert") { ignoreCert = true; }
                if (arg == "--all") { inaddrany = true; }
                if (arg == "--inaddrany") { inaddrany = true; }
                if (arg == "--service") { runAsService = true; }
                if ((arg == "--pass") && (i < (args.Length - 1))) { password = args[i + 1]; }
                if ((arg == "--user") && (i < (args.Length - 1))) { username = args[i + 1]; }
                if ((arg == "--password") && (i < (args.Length - 1))) { password = args[i + 1]; }
                if ((arg == "--username") && (i < (args.Length - 1))) { username = args[i + 1]; }
                if ((arg == "--token") && (i < (args.Length - 1))) { token = args[i + 1]; }
                if (arg == "--emailtoken") { token = "**email**"; }
                if (arg == "--smstoken") { token = "**sms**"; }
                if ((arg == "--serverid") && (i < (args.Length - 1))) { serverid = args[i + 1]; }
                if ((arg == "--serverhttpshash") && (i < (args.Length - 1))) { serverTlsHash = args[i + 1]; }
                if ((arg == "--servertlshash") && (i < (args.Length - 1))) { serverTlsHash = args[i + 1]; }
                if (arg == "--install") { Log("Installing service..."); ManagedInstallerClass.InstallHelper(new string[] { Assembly.GetExecutingAssembly().Location }); return; }
                if (arg == "--uninstall") { Log("Uninstalling service..."); ManagedInstallerClass.InstallHelper(new string[] { "/u", Assembly.GetExecutingAssembly().Location }); return; }
                if (arg == "--start") {
                    Log("Starting service...");
                    ServiceController service = new ServiceController("MeshCentralRouter");
                    try { service.Start(); service.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromMilliseconds(20000)); } catch (Exception ex) { Log(ex.ToString()); }
                    return;
                }
                if (arg == "--stop")
                {
                    Log("Stopping service...");
                    ServiceController service = new ServiceController("MeshCentralRouter");
                    try { service.Stop(); service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromMilliseconds(20000)); } catch (Exception ex) { Log(ex.ToString()); }
                    return;
                }
            }

            if (runAsService)
            {
                ServiceBase[] ServicesToRun;
                ServicesToRun = new ServiceBase[] { new MainService() };
                ServiceBase.Run(ServicesToRun);
            }
            else
            {
                if ((action == null) || (help == true))
                {
                    Console.WriteLine("This tool is used along with a MeshCentral account to map a local TCP port to a remote port on any computer on your MeshCentral account. This action requires many arguments, to avoid specifying them all it's best to download the meshaction.txt file from the web site and place it in the current folder. Example usage:");
                    Console.WriteLine("");
                    Console.WriteLine("  (Place meshaction.txt file in current folder)");
                    Console.WriteLine("  " + fi.Name + " --pass myAccountPassword");
                    Console.WriteLine("");
                    Console.WriteLine("You can also install and start this tool as a Windows Service:");
                    Console.WriteLine("");
                    Console.WriteLine("  " + fi.Name + " --install");
                    Console.WriteLine("  " + fi.Name + " --start");
                    Console.WriteLine("  " + fi.Name + " --stop");
                    Console.WriteLine("  " + fi.Name + " --uninstall");
                    Console.WriteLine("");
                    Console.WriteLine("When running as a Windows service, the account password must be in the action.txt file.");
                    Environment.Exit(0);
                    return;
                }

                if ((serverid != null) && (url == null))
                {
                    // Discover the server
                    Log("Searching for server...");
                    discovery = new MeshDiscovery();
                    discovery.OnNotify += Discovery_OnNotify;
                    discovery.MulticastPing();
                }
                else
                {
                    ConnectToServer();
                }

                // Wait until exit
                while (true) { System.Threading.Thread.Sleep(5000); } // Wait here.
            }
        }

        public static void Start()
        {
            if ((meshcentral != null) || (discovery != null)) return;
            if ((serverid != null) && (url == null))
            {
                // Discover the server
                Log("Searching for server...");
                discovery = new MeshDiscovery();
                discovery.OnNotify += Discovery_OnNotify;
                discovery.MulticastPing();
            }
            else
            {
                ConnectToServer();
            }
        }
        public static void Stop()
        {

        }

        private static void ConnectToServer()
        {
            // Check arguments
            if (url == null) { Log("Missing URL."); Environment.Exit(0); return; }
            if (username == null) { Log("Missing username."); Environment.Exit(0); return; }
            if (password == null) { Log("Missing password."); Environment.Exit(0); return; }
            if ((PortMaps == null) || (PortMaps.Count == 0)) { Log("No port mappings provided."); Environment.Exit(0); return; }
            foreach (PortMap map in PortMaps)
            {
                if (map.remoteNodeId == null) { Log("Missing remote node id."); Environment.Exit(0); return; }
                if (map.remotePort == 0) { Log("Missing remote port."); Environment.Exit(0); return; }
            }

            // Setup TLS connection
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            ServicePointManager.ServerCertificateValidationCallback += new System.Net.Security.RemoteCertificateValidationCallback(RemoteCertificateValidationCallback);

            // Setup MeshCentral server object
            var serverUrl = url.Replace("/meshrelay.ashx", "/control.ashx");
            meshcentral = new MeshCentralServer();
            meshcentral.serverid = serverid;
            meshcentral.ignoreCert = ignoreCert;
            meshcentral.okCertHash = serverTlsHash;
            meshcentral.onStateChanged += Server_onStateChanged;
            meshcentral.onNodesChanged += Server_onNodesChanged;
            meshcentral.connect(new Uri(serverUrl), username, password, token);
        }

        private static void Discovery_OnNotify(MeshDiscovery sender, IPEndPoint source, IPEndPoint local, string agentCertHash, string xurl, string name, string info)
        {
            if (url != null) return;
            if (agentCertHash == serverid)
            {
                url = xurl.Replace("https://", "wss://") + "meshrelay.ashx";
                discovery.Dispose();
                discovery = null;
                ConnectToServer();
            }
        }

        private static void Server_onNodesChanged(bool fullRefresh)
        {
            if (mappers.Count == 0)
            {
                Log(meshcentral.nodes.Keys.Count + " device(s) in this account.");
                foreach (PortMap map in PortMaps)
                {
                    if (meshcentral.nodes.ContainsKey(map.remoteNodeId) == false) { Log("This account does not contain this device."); Environment.Exit(0); return; }

                    NodeClass node = meshcentral.nodes[map.remoteNodeId];

                    // Start the port map.
                    MeshMapper mapper = new MeshMapper();
                    mapper.xdebug = debug;
                    mapper.inaddrany = inaddrany;
                    mapper.certhash = meshcentral.certHash;
                    mapper.onStateMsgChanged += Mapper_onStateMsgChanged;
                    string serverurl = url + "?nodeid=" + node.nodeid;
                    /*
                    int keyIndex = host.IndexOf("?key=");
                    if (keyIndex >= 0)
                    {
                        serverurl = "wss://" + host.Substring(0, keyIndex) + "/" + ((node.mtype == 3) ? "local" : "mesh") + "relay.ashx?nodeid=" + node.nodeid + "&key=" + host.Substring(keyIndex + 5);
                    }
                    else
                    {
                        serverurl = "wss://" + host + "/" + ((node.mtype == 3) ? "local" : "mesh") + "relay.ashx?nodeid=" + node.nodeid;
                    }
                    */
                    if (map.protocol == 1)
                    {
                        serverurl += ("&tcpport=" + map.remotePort);
                        if (map.remoteIP != null) { serverurl += "&tcpaddr=" + map.remoteIP; }
                    }
                    else if (map.protocol == 2)
                    {
                        serverurl += ("&udpport=" + map.remotePort);
                        if (map.remoteIP != null) { serverurl += "&udpaddr=" + map.remoteIP; }
                    }
                    mapper.start(meshcentral, map.protocol, map.localPort, serverurl, map.remotePort, map.remoteIP);
                    mappers.Add(mapper);
                }
            }
        }

        private static void Server_onStateChanged(int state)
        {
            if (state == 0)
            {
                if (meshcentral.disconnectMsg == "cert")
                {
                    Log("Untrusted server TLS certificate.");
                    Log("Add: --servertlshash " + meshcentral.disconnectCert.GetCertHashString());
                }
                else if (meshcentral.disconnectMsg != null)
                {
                    Log("Disconnected: " + meshcentral.disconnectMsg);
                }
                else
                {
                    Log("Disconnected.");
                }
                Environment.Exit(0);
            }
            if (state == 1) { Log("Connecting to " + meshcentral.wsurl); }
            if (state == 2) { Log("Connected."); }
        }

        private static void Mapper_onStateMsgChanged(MeshMapper sender, string statemsg)
        {
            Log("Port Mapping: " + statemsg);
        }

        private static bool RemoteCertificateValidationCallback(object sender, X509Certificate certificate, X509Chain chain, System.Net.Security.SslPolicyErrors sslPolicyErrors)
        {
            if (meshcentral.ignoreCert) return true;
            if (meshcentral.connectionState < 2)
            {
                // Normal certificate check
                if (chain.Build(new X509Certificate2(certificate)) == true) { meshcentral.certHash = webSocketClient.GetMeshKeyHash(certificate); return true; }
                if ((meshcentral.okCertHash != null) && ((meshcentral.okCertHash == certificate.GetCertHashString()) || (meshcentral.okCertHash == webSocketClient.GetMeshKeyHash(certificate)) || (meshcentral.okCertHash == webSocketClient.GetMeshCertHash(certificate)))) { meshcentral.certHash = webSocketClient.GetMeshKeyHash(certificate); return true; }
                if ((meshcentral.okCertHash2 != null) && ((meshcentral.okCertHash2 == certificate.GetCertHashString()) || (meshcentral.okCertHash2 == webSocketClient.GetMeshKeyHash(certificate)) || (meshcentral.okCertHash2 == webSocketClient.GetMeshCertHash(certificate)))) { meshcentral.certHash = webSocketClient.GetMeshKeyHash(certificate); return true; }
                if (meshcentral.serverid != null) { meshcentral.certHash = webSocketClient.GetMeshKeyHash(certificate); return true; }
                meshcentral.certHash = null;
                meshcentral.disconnectMsg = "cert";
                meshcentral.disconnectCert = new X509Certificate2(certificate);
            }
            else
            {
                // Tunnel security check
                if ((meshcentral.certHash != null) && ((meshcentral.certHash == certificate.GetCertHashString()) || (meshcentral.certHash == webSocketClient.GetMeshKeyHash(certificate)) || (meshcentral.certHash == webSocketClient.GetMeshCertHash(certificate)))) { return true; }
            }
            return false;
        }

    }
}
