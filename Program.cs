using System;
using System.IO;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Web.Script.Serialization;
using System.Net;

namespace MeshCentralRouterCmd
{
    class Program
    {
        static bool debug = false;
        static bool tlsdump = false;
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
        static MeshMapper mapper = null;
        static int protocol = 1; // 1 = TCP, 2 = UDP
        static int localPort = 0; // 0 = Any
        static int remotePort = 0;
        static string remoteIP = null;
        static string remoteNodeId = null;

        [STAThread]
        static void Main(string[] args)
        {
            Console.WriteLine("MeshCentral Router CMD.");

            // Parse the meshaction.txt file
            string action = null;
            try { action = File.ReadAllText("meshaction.txt"); } catch (Exception) { }
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
                    if (keyl == "serverid") { serverid = (string)jsonAction[key]; }
                    if (keyl == "serverhttpshash") { serverTlsHash = (string)jsonAction[key]; }
                    if (keyl == "remotetarget") { remoteIP = (string)jsonAction[key]; }
                    if (keyl == "remoteport") { remotePort = (int)jsonAction[key]; }
                    if (keyl == "localport") { localPort = (int)jsonAction[key]; }
                    if (keyl == "remotenodeid") { remoteNodeId = (string)jsonAction[key]; }
                }
            }

            // Parse arguments
            for (int i = 0; i < args.Length; i++)
            {
                string arg = args[i].ToLower();
                if (arg == "--debug") { debug = true; }
                if (arg == "--tlsdump") { tlsdump = true; }
                if (arg == "--ignorecert") { ignoreCert = true; }
                if (arg == "--all") { inaddrany = true; }
                if (arg == "--inaddrany") { inaddrany = true; }
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
            }

            if ((serverid != null) && (url == null))
            {
                // Discover the server
                Console.WriteLine("Searching for server...");
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

        private static void ConnectToServer()
        {
            // Check arguments
            if (url == null) { Console.WriteLine("Missing URL."); Environment.Exit(0); return; }
            if (username == null) { Console.WriteLine("Missing username."); Environment.Exit(0); return; }
            if (password == null) { Console.WriteLine("Missing password."); Environment.Exit(0); return; }
            if (remoteNodeId == null) { Console.WriteLine("Missing remote node id."); Environment.Exit(0); return; }
            if (remotePort == 0) { Console.WriteLine("Missing remote port."); Environment.Exit(0); return; }

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
            if (agentCertHash == serverid) {
                url = xurl.Replace("https://", "wss://") + "meshrelay.ashx";
                discovery.Dispose();
                discovery = null;
                ConnectToServer();
            }
        }

        private static void Server_onNodesChanged(bool fullRefresh)
        {
            if (mapper == null)
            {
                Console.WriteLine(meshcentral.nodes.Keys.Count + " device(s) in this account.");
                if (meshcentral.nodes.ContainsKey(remoteNodeId) == false) { Console.WriteLine("This account does not contain this device."); Environment.Exit(0); return; }

                NodeClass node = meshcentral.nodes[remoteNodeId];

                // Start the port map.
                mapper = new MeshMapper();
                mapper.xdebug = debug;
                mapper.inaddrany = inaddrany;
                mapper.certhash = meshcentral.certHash;
                mapper.onStateMsgChanged += Mapper_onStateMsgChanged; ;
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
                if (protocol == 1)
                {
                    serverurl += ("&tcpport=" + remotePort);
                    if (remoteIP != null) { serverurl += "&tcpaddr=" + remoteIP; }
                }
                else if (protocol == 2)
                {
                    serverurl += ("&udpport=" + remotePort);
                    if (remoteIP != null) { serverurl += "&udpaddr=" + remoteIP; }
                }
                mapper.start(meshcentral, protocol, localPort, serverurl, remotePort, remoteIP);
            }
        }

        private static void Server_onStateChanged(int state)
        {
            if (state == 0) {
                if (meshcentral.disconnectMsg == "cert")
                {
                    Console.WriteLine("Untrusted server TLS certificate.");
                    Console.WriteLine("Add: --servertlshash " + meshcentral.disconnectCert.GetCertHashString());
                }
                else if (meshcentral.disconnectMsg != null)
                {
                    Console.WriteLine("Disconnected: " + meshcentral.disconnectMsg);
                }
                else
                {
                    Console.WriteLine("Disconnected.");
                }
                Environment.Exit(0);
            }
            if (state == 1) { Console.WriteLine("Connecting to " + meshcentral.wsurl); }
            if (state == 2) { Console.WriteLine("Connected."); }
        }

        private static void Mapper_onStateMsgChanged(string statemsg)
        {
            Console.WriteLine("Port Mapping: " + statemsg);
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
