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
using System.Net;
using System.Text;
using System.Threading;
using System.Net.WebSockets;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace MeshCentralRouterCmd
{
    public class webSocketClient : IDisposable
    {
        private ClientWebSocket ws = null; // Native Windows WebSocket
        private CancellationTokenSource CTS;
        private ConnectionStates state = 0;
        private Uri url = null;
        private string tlsCertFingerprint = null;
        private string tlsCertFingerprint2 = null;
        public bool debug = false;
        public bool tlsdump = false;
        public Dictionary<string, string> extraHeaders = null;
        public TLSCertificateCheck TLSCertCheck = TLSCertificateCheck.Verify;
        public X509Certificate2 failedTlsCert = null;
        private bool receivePaused = false;
        private SemaphoreSlim receiveLock = new SemaphoreSlim(1, 1);
        private Object pauseLock = new Object();

        public bool tunneling;
        public Object tag;
        public Object[] tag2;
        public int id;
        public IPEndPoint endpoint;

        public enum ConnectionStates
        {
            Disconnected = 0,
            Connecting = 1,
            Connected = 2
        }

        public enum TLSCertificateCheck
        {
            Ignore = 0,
            Fingerprint = 1,
            Verify = 2
        }

        public enum ConnectionErrors
        {
            NoError = 0
        }

        private void TlsDump(string direction, byte[] data, int offset, int len) { if (tlsdump) { try { File.AppendAllText("debug.log", direction + ": " + BitConverter.ToString(data, offset, len).Replace("-", string.Empty) + "\r\n"); } catch (Exception) { } } }

        public delegate void onBinaryDataHandler(webSocketClient sender, byte[] data, int offset, int length, int orglen);
        public event onBinaryDataHandler onBinaryData;
        public delegate void onStringDataHandler(webSocketClient sender, string data, int orglen);
        public event onStringDataHandler onStringData;
        public delegate void onDebugMessageHandler(webSocketClient sender, string msg);
        public event onDebugMessageHandler onDebugMessage;
        public delegate void onStateChangedHandler(webSocketClient sender, ConnectionStates state);
        public event onStateChangedHandler onStateChanged;
        public delegate void onSendOkHandler(webSocketClient sender);
        public event onSendOkHandler onSendOk;

        public ConnectionStates State { get { return state; } }

        private void SetState(ConnectionStates newstate)
        {
            if (state == newstate) return;
            state = newstate;
            if (onStateChanged != null) { onStateChanged(this, state); }
        }

        public void Dispose()
        {
            if (ws != null)
            {
                if (ws.State == WebSocketState.Open)
                {
                    CTS.CancelAfter(TimeSpan.FromSeconds(2));
                    ws.CloseOutputAsync(WebSocketCloseStatus.Empty, "", CancellationToken.None);
                    ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "", CancellationToken.None);
                }
                try { if (ws != null) { ws.Dispose(); ws = null; } } catch (Exception) { }
                try { if (CTS != null) { CTS.Dispose(); CTS = null; } } catch (Exception) { }
            }
            SetState(ConnectionStates.Disconnected);
        }

        public void Log(string msg)
        {
            if (onDebugMessage != null) { onDebugMessage(this, msg); }
            if (debug) { try { File.AppendAllText("debug.log", DateTime.Now.ToString("HH:mm:tt.ffff") + ": WebSocket: " + msg + "\r\n"); } catch (Exception) { } }
        }

        private async Task ConnectAsync(Uri url)
        {
            if (CTS != null) CTS.Dispose();
            CTS = new CancellationTokenSource();
            try { await ws.ConnectAsync(url, CTS.Token); } catch (Exception ex) {
                Console.WriteLine("Unable to connect to server: " + url);
                Console.WriteLine(ex.Message);
                SetState(0);
                return;
            }
            await Task.Factory.StartNew(ReceiveLoop, CTS.Token, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        }

        public async Task DisconnectAsync()
        {
            if (ws == null) return;
            if (ws.State == WebSocketState.Open)
            {
                CTS.CancelAfter(TimeSpan.FromSeconds(2));
                await ws.CloseOutputAsync(WebSocketCloseStatus.Empty, "", CancellationToken.None);
                await ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "", CancellationToken.None);
            }
            ws.Dispose();
            ws = null;
            CTS.Dispose();
            CTS = null;
        }

        public bool Start(Uri url, string tlsCertFingerprint, string tlsCertFingerprint2)
        {
            if (state != ConnectionStates.Disconnected) return false;
            SetState(ConnectionStates.Connecting);
            this.url = url;
            if (tlsCertFingerprint != null) { this.tlsCertFingerprint = tlsCertFingerprint.ToUpper(); }
            if (tlsCertFingerprint2 != null) { this.tlsCertFingerprint2 = tlsCertFingerprint2.ToUpper(); }

            ws = new ClientWebSocket();
            Log("Websocket (native) Start, URL=" + ((url == null) ? "(NULL)" : url.ToString()));
            if (extraHeaders != null) { foreach (var key in extraHeaders.Keys) { ws.Options.SetRequestHeader(key, extraHeaders[key]); } }
            Task t = ConnectAsync(url);
            return true;
        }

        public string Base64Encode(string plainText)
        {
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
            return System.Convert.ToBase64String(plainTextBytes);
        }

        public string Base64Decode(string base64EncodedData)
        {
            var base64EncodedBytes = System.Convert.FromBase64String(base64EncodedData);
            return System.Text.Encoding.UTF8.GetString(base64EncodedBytes);
        }
        
        // Return a modified base64 SHA384 hash string of the certificate public key
        public static string GetMeshKeyHash(X509Certificate cert)
        {
            return ByteArrayToHexString(new SHA384Managed().ComputeHash(cert.GetPublicKey()));
        }

        // Return a modified base64 SHA384 hash string of the certificate
        public static string GetMeshCertHash(X509Certificate cert)
        {
            return ByteArrayToHexString(new SHA384Managed().ComputeHash(cert.GetRawCertData()));
        }

        public static string ByteArrayToHexString(byte[] Bytes)
        {
            StringBuilder Result = new StringBuilder(Bytes.Length * 2);
            string HexAlphabet = "0123456789ABCDEF";
            foreach (byte B in Bytes) { Result.Append(HexAlphabet[(int)(B >> 4)]); Result.Append(HexAlphabet[(int)(B & 0xF)]); }
            return Result.ToString();
        }

        public int SendString(string data)
        {
            if (state != ConnectionStates.Connected) return 0;
            Log("WebSocketClient-SEND-String: " + data);
            byte[] buf = UTF8Encoding.UTF8.GetBytes(data);
            return SendFragment(buf, 0, buf.Length, 129);
        }

        public int SendBinary(byte[] data)
        {
            Log("WebSocketClient-SEND-Binary-Len:" + data.Length);
            return SendFragment(data, 0, data.Length, 130);
        }

        public int SendBinary(byte[] data, int offset, int len) {
            Log("WebSocketClient-SEND-Binary-Len:" + len);
            return SendFragment(data, offset, len, 130);
        }

        public int SendPing(byte[] data, int offset, int len)
        {
            Log("WebSocketClient-SEND-Ping");
            return SendFragment(null, 0, 0, 137);
        }

        public int SendPong(byte[] data, int offset, int len)
        {
            Log("WebSocketClient-SEND-Pong");
            return SendFragment(null, 0, 0, 138);
        }

        // This controls the flow of fragments being sent, queuing send operations if needed
        private Task pendingSend = null;
        private List<pendingSendClass> pendingSends = new List<pendingSendClass>();
        private class pendingSendClass
        {
            public pendingSendClass(byte[] data, int offset, int len, byte op) { this.data = data; this.offset = offset; this.len = len; this.op = op; }
            public byte[] data;
            public int offset;
            public int len;
            public byte op;
        }

        // Fragment op code (129 = text, 130 = binary)
        public int SendFragment(byte[] data, int offset, int len, byte op)
        {
            if (ws == null) return 0;
            TlsDump("Out(" + op + ")", data, offset, len);
            lock (pendingSends)
            {
                if (pendingSend != null)
                {
                    // A send operating is already being processes, queue this send.
                    pendingSends.Add(new pendingSendClass(data, offset, len, op));
                }
                else
                {
                    // No send operations being performed now, send this fragment now.
                    ArraySegment<byte> arr = new ArraySegment<byte>(data, offset, len);
                    WebSocketMessageType msgType = ((op == 129) ? WebSocketMessageType.Text : WebSocketMessageType.Binary);
                    pendingSend = ws.SendAsync(arr, msgType, true, CTS.Token);
                    pendingSend.ContinueWith(antecedent => SendFragmentDone());
                }
            }
            return len;
        }

        // Called when a fragment is done sending. We look to send the next one or signal that we can accept more data
        private void SendFragmentDone()
        {
            bool q = false;
            lock (pendingSends)
            {
                pendingSend = null;
                if (pendingSends.Count > 0)
                {
                    // There is more send operation pending, send the next one now.
                    pendingSendClass p = pendingSends[0];
                    pendingSends.RemoveAt(0);
                    ArraySegment<byte> arr = new ArraySegment<byte>(p.data, p.offset, p.len);
                    WebSocketMessageType msgType = ((p.op == 129) ? WebSocketMessageType.Text : WebSocketMessageType.Binary);
                    pendingSend = ws.SendAsync(arr, msgType, true, CTS.Token);
                    pendingSend.ContinueWith(antecedent => SendFragmentDone());
                } else { q = true; } // No pending send operations, signal ok to send more.
            }
            if ((q == true) && (onSendOk != null)) { onSendOk(this); }
        }

        private static Mutex ReceivePauseMutex = null;

        private async Task ReceiveLoop()
        {
            SetState(ConnectionStates.Connected);
            var loopToken = CTS.Token;
            MemoryStream outputStream = null;
            WebSocketReceiveResult receiveResult = null;
            var buffer = new byte[8192];
            ArraySegment<byte> bufferEx = new ArraySegment<byte>(buffer);
            try
            {
                while (!loopToken.IsCancellationRequested)
                {
                    outputStream = new MemoryStream(8192);
                    do
                    {
                        receiveResult = await ws.ReceiveAsync(bufferEx, CTS.Token);
                        if (receiveResult.MessageType != WebSocketMessageType.Close)
                            outputStream.Write(buffer, 0, receiveResult.Count);
                    }
                    while (!receiveResult.EndOfMessage);
                    if (receiveResult.MessageType == WebSocketMessageType.Close) break;
                    outputStream.Position = 0;

                    receiveLock.Wait(); // Pause reading if needed
                    receiveLock.Release();

                    if (receiveResult.MessageType == WebSocketMessageType.Text)
                    {
                        Log("Websocket got string data, len = " + (int)outputStream.Length);
                        TlsDump("InStr", outputStream.GetBuffer(), 0, (int)outputStream.Length);
                        if (onStringData != null) { onStringData(this, UTF8Encoding.UTF8.GetString(outputStream.GetBuffer(), 0, (int)outputStream.Length), (int)outputStream.Length); }
                    }
                    else if (receiveResult.MessageType == WebSocketMessageType.Binary)
                    {
                        Log("Websocket got binary data, len = " + (int)outputStream.Length);
                        TlsDump("InBin", outputStream.GetBuffer(), 0, (int)outputStream.Length);
                        if (onBinaryData != null) { onBinaryData(this, outputStream.GetBuffer(), 0, (int)outputStream.Length, (int)outputStream.Length); }
                    }
                }
            }
            catch (TaskCanceledException) { }
            finally
            {
                outputStream?.Dispose();
                SetState(0);
            }
        }

        public void Pause()
        {
            lock (pauseLock) { if (receivePaused == false) { receivePaused = true; receiveLock.Wait(); } }
        }

        public void Resume()
        {
            lock (pauseLock) { if (receivePaused != false) { receivePaused = false; receiveLock.Release(); } }
        }

    }

}
