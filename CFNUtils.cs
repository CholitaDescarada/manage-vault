using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.DirectoryServices.AccountManagement;
using System.Diagnostics;
using System.Configuration;
using System.Collections.Specialized;
using System.Net;
using System.IO;
using CyberArk.AIM.NetPasswordSDK;
using CyberArk.AIM.NetPasswordSDK.Exceptions;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.DirectoryServices.Protocols;


namespace CfnUtils
{
    public static class CFNUtils
    {



        public static log4net.ILog logger;

        public static string server_address;

        public static string vault_user;

        public static bool use_v10;

        public static string g_full_admin;

        public static string vault_user_object_name;

        public static string app_id;

        public static string password_manager;

        public static string vault_user_safe_name;

        public static string env;

        public static bool useSSL;

        static CFNUtils() {
            logger = log4net.LogManager.GetLogger("CFNUtils");

            server_address = ConfigurationManager.AppSettings["VaultServer"];
            vault_user = ConfigurationManager.AppSettings["VaultUser"];
            use_v10 = String.IsNullOrEmpty(ConfigurationManager.AppSettings["UseV10"]) ? false : ConfigurationManager.AppSettings["UseV10"].Equals("Y");
            g_full_admin = ConfigurationManager.AppSettings["GFullAdmin"];
            vault_user_object_name = ConfigurationManager.AppSettings["VaultUserObjectName"];
            app_id = ConfigurationManager.AppSettings["AppID"];
            //password_manager = String.IsNullOrEmpty(ConfigurationManager.AppSettings["PasswordManager"]) ? "CPM-MARS-1" : ConfigurationManager.AppSettings["PasswordManager"];
            password_manager = String.IsNullOrEmpty(ConfigurationManager.AppSettings["PasswordManager"]) ? "PasswordManager" : ConfigurationManager.AppSettings["PasswordManager"];
            vault_user_safe_name = String.IsNullOrEmpty(ConfigurationManager.AppSettings["VaultUserSafeName"]) ? "CF-AIM-W61" : ConfigurationManager.AppSettings["VaultUserSafeName"];
            env =  String.IsNullOrEmpty(ConfigurationManager.AppSettings["Env"]) ? "PRD" : ConfigurationManager.AppSettings["Env"];
            useSSL = String.IsNullOrEmpty(ConfigurationManager.AppSettings["UseSSL"]) ? false : ConfigurationManager.AppSettings["UseSSL"].Equals("Y");

            System.Net.ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12;
        }


        public static string LogonVault(string username, string password)
        {
            string session_token = null;
            WebClient client = new WebClient();
            client.Headers[HttpRequestHeader.ContentType] = "application/json";
            logger.Info("Logon vault...");
            try {
                //https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/CyberArk%20Authentication%20-%20Logon_v10.htm
                string logon_endpoint = ConfigurationManager.AppSettings["UseV10"].Equals("Y") ? "/PasswordVault/API/auth/Cyberark/Logon" : "/PasswordVault/WebServices/auth/Cyberark/CyberArkAuthenticationService.svc/Logon";
                Uri uri = new Uri("https://" + server_address + logon_endpoint);

                //string payload = "{\"username\": \"" + username + "\", \"password\": \"" + password + "\" }";
                JObject payload = new JObject(new JProperty("username", username), new JProperty("password", password));

                //logger.Debug(String.Format("uri: {0}\tpayload: {1}", uri.ToString(), payload.ToString()));

                //var response = client.UploadString(uri, payload);
                var response = client.UploadString(uri, payload.ToString());
                if (use_v10) {
                    session_token = response.Replace("\"", "");
                }
                else {
                    dynamic json = JsonConvert.DeserializeObject(response);
                    session_token = json.CyberArkLogonResult;
                }

                //Analyser la réponse pour identifier si c'est vraiment un token...
                //logger.Debug(String.Format("session_token: {0}\nresponse: {1}", session_token, response));
                Regex regex = new Regex(@"^[a-zA-Z0-9]+$");
                if (!regex.IsMatch(session_token)) {
                    logger.Error(String.Format("Returned value is not a valid token: {0}", session_token));
                    return null;
                }
            }
            catch (Exception ex) {
                logger.Error(String.Format("Unable to get session token: {0}", ex.ToString()));
                return null;
            }
            finally {
                client.Dispose();
            }

            logger.Debug(String.Format("Obtained session token: {0}", session_token));
            return session_token;
        }

        public static int LogoffVault(string session_token) 
        {
            //int rc = 0;
            logger.Info("Logoff vault ...");
            ServerResponse serverResponse = SendHttpRequest(session_token, "POST", "/PasswordVault/WebServices/auth/Cyberark/CyberArkAuthenticationService.svc/Logoff", "");
            if (IsFailure(serverResponse)) {
                //rc = 1;
                return 1;
            }
            else {
                return 0;
            }

            //return rc;
        }

        public static ServerResponse SendHttpRequest(string session_token, string method, string endpoint, string payload)
        {
            WebClient client = new WebClient();
            client.Headers[HttpRequestHeader.ContentType] = "application/json";
            client.Headers[HttpRequestHeader.Authorization] = session_token;

            //logger.Info(String.Format("server_address: {0}\tendpoint: {1}", server_address + endpoint));

            //Debug
            /*
            if (payload.Contains("G_CF-AIM-XXX-APP_HP_XXX_Gst")) {
                logger.Debug("On entre dans la fonction de CFNUtils...");
            }
            */

            Uri uri = new Uri(String.Format("https://{0}{1}", server_address, endpoint));
            string response = "";
            WebExceptionStatus status_code = WebExceptionStatus.Success;
            CyberarkError error = null;
            try {
                if (method.ToUpper().Equals("GET")) {
                    response = client.DownloadString(uri);
                }
                else {
                    response = client.UploadString(uri, method, payload);
                }
            }
            catch (WebException ex) {
                response = GetServerErrorMessages(ex);

                //Debug
                /*
                if (payload.Contains("G_CF-AIM-XXX-APP_HP_XXX_Gst")) {
                    logger.Debug(String.Format("Custom debug - response: {0}", response));
                }
                */

                if (!String.IsNullOrEmpty(response)) {
                    try {
                        error = JsonConvert.DeserializeObject<CyberarkError>(response);
                    }
                    catch (JsonSerializationException e) {
                        logger.Debug("Failed to parse Cyberark Error response: " + e.Message);
                    }
                }
                status_code = ex.Status;
            }
            catch (Exception e) {
                logger.Error("Unexpected error: " + e.Message);
                status_code = WebExceptionStatus.UnknownError;
            }
            finally {
                client.Dispose();
            }

            logger.Debug("Response: " + response + System.Environment.NewLine + "StatusCode: " + status_code.ToString());
            return new ServerResponse(response, error, status_code);
        }

        private static string GetServerErrorMessages(WebException ex)
        {
            String serverResponse = "";
            logger.Error(ex.Message.ToString());
            if (ex.Response != null)
            {
                try
                {
                    StreamReader reader = new StreamReader(ex.Response.GetResponseStream());
                    serverResponse += reader.ReadToEnd();
                }
                catch (Exception e)
                {
                    logger.Debug("Failed to read server response stream: " + e.Message);
                }
            }
            return serverResponse;
        }

        public static int RunPacli(string workingDir, string content)
        {
            int rc = 0;
            try {
                Process p = new Process();
                p.StartInfo.RedirectStandardOutput = true;
                p.StartInfo.RedirectStandardError = true;
                p.StartInfo.UseShellExecute = false;
                p.StartInfo.CreateNoWindow = true;
                p.StartInfo.WorkingDirectory = workingDir;
                p.StartInfo.FileName = workingDir + "\\Pacli.exe";

                string error = "";
                foreach (String line in content.Split('\n'))
                {
                    p.StartInfo.Arguments = line.Trim();
                    logger.Debug("Executing PACLI command: " + line);
                    p.Start();
                    error = p.StandardError.ReadToEnd();
                    p.WaitForExit();
                    if (p.ExitCode != 0)
                    {
                        if (!error.Contains("ITATS673E"))
                        {
                            logger.Error("PACLI error: " + error);
                            rc = 1;
                        }
                    }
                }
            }
            catch (Exception e)
            {
                logger.Error("Error while executing PACLI commands: " + e.Message);
            }
            return rc;
        }

        public class ServerResponse
        {
            public string response;
            public CyberarkError cyberarkError;
            public WebExceptionStatus statusCode;

            public ServerResponse(string response, CyberarkError error, WebExceptionStatus code)
            {
                this.response = response;
                this.cyberarkError = error;
                this.statusCode = code;
            }
        }

        public class CyberarkError
        {
            public string ErrorMessage { get; set; }
            public string ErrorCode { get; set; }
        }

        public static bool IsFailure(ServerResponse serverResponse)
        {
            return serverResponse.cyberarkError != null || !serverResponse.statusCode.Equals(WebExceptionStatus.Success);
        }


        public static string GeneratePacliCmds(string templateFile, NameValueCollection replacementDict)
        {
            try
            {
                StreamReader reader = new StreamReader(templateFile);
                string content = reader.ReadToEnd();
                reader.Close();
                foreach (string placeHolder in replacementDict.AllKeys)
                {
                    content = content.Replace(placeHolder, replacementDict[placeHolder]);
                }
                //StreamWriter writer = new StreamWriter(dstFile);
                //writer.Write(content);
                //writer.Close();
                return content;
            }
            catch (IOException e)
            {
                logger.Error("Failed to generate PACLI command file: " + e.Message);
                return null;
            }

        }

        public static string CleanString(string dirtyString)
        {
            string removeChars = "?&^$#@!+<>\\/«»";
            string result = dirtyString;

            foreach (char c in removeChars)
            {
                result = result.Replace(c.ToString(), string.Empty);
            }

            return result;
        }

        public static bool IsProdEnv() {
            return CFNUtils.env.ToUpper().Equals("PRD") || CFNUtils.server_address.Equals("coffrefort.intranatixis.com") || CFNUtils.server_address.Equals("asiavault.intranatixis.com");
        }

        public static string AIMGetPassword(string safeName, string appId, string objectName) {
            PSDKPasswordRequest passRequest = new PSDKPasswordRequest();
            passRequest.AppID = appId;
            passRequest.Safe = safeName;
            passRequest.Folder = "root";
            passRequest.Object = objectName;
            PSDKPassword password = PasswordSDK.GetPassword(passRequest);
          
            return password.Content;
        }

        public static int RunPacliCmds(string folder, string templateFileName, NameValueCollection replacementDict)
        {

            int rc = 0;
            string templateFile = folder + "\\" + templateFileName;
            string content = GeneratePacliCmds(templateFile, replacementDict);

            if (content != null)
            {
                logger.Info("Run PACLI commands...");
                rc = RunPacli(folder, content);
            }
            else
            {
                rc = 2;
            }
            return rc;
        }

        public static PrincipalContext ConnectAD(string ADserver, string ADdomain, string ADuser, string ADpassword)
        {
            // Querying Active Directory
            // System.Security.Principal.WindowsImpersonationContext impersonationContext;
            // impersonationContext = ((System.Security.Principal.WindowsIdentity)User.Identity).Impersonate();

            PrincipalContext ctx = null;
            try {
                if (useSSL) {

                    ADserver = ADserver + ":636";
                    logger.Debug("--> Connecting to " + ADserver);
                    ContextOptions options = ContextOptions.SimpleBind | ContextOptions.SecureSocketLayer;
                    ctx = new PrincipalContext(ContextType.Domain, ADserver, ADdomain, options, ADuser, ADpassword);
                } else {
                    ctx = new PrincipalContext(ContextType.Domain, ADserver, ADdomain, ADuser, ADpassword);
                }

            } catch (Exception ex) {
                logger.Error("Failed to connect to AD: " + ex.ToString());
                return null;
            }

            return ctx;
        }

        public static LdapConnection LdapConnectAD(string ADserver, string ADdomain, string username, string password)
        {
            // Querying Active Directory
            //LdapConnection ldapConn = new LdapConnection(ADdomain);
            if (useSSL)
            {
                ADserver = ADserver + ":636";

            }
            LdapConnection ldapConn = new LdapConnection(ADserver);
            try
            {       
                   
                    logger.Debug("--> Connecting to " + ADserver);
                    var networkCredential = new NetworkCredential(username, password, ADdomain);
                    ldapConn.SessionOptions.VerifyServerCertificate = new VerifyServerCertificateCallback((con, cer) => true);
                    if (useSSL)
                    {
                        ldapConn.SessionOptions.SecureSocketLayer = useSSL;
                        ldapConn.SessionOptions.ProtocolVersion = 3;
                    }
                   
                    ldapConn.AuthType = AuthType.Negotiate;
                    ldapConn.Bind(networkCredential);
                    logger.Info("Bind OK.");
            }
            catch (LdapException ex)
            {
                if (!ex.ErrorCode.Equals(0x31))
                {
                    logger.Error("Failed to connect to AD using LdapConnection: " + ex.ToString());
                    return null;
                }
                else
                {
                    logger.Error("Failed to connect to AD using LdapConnection: invalid credentials");
                    return null;
                }
            }

            return ldapConn;
        }

        public static string FindAdAccountLdap(LdapConnection ldapConn, string searchFilter, string attributeName, string scope)
        {
            string samAccountName = null;

            try {
                logger.Info("Searching account " + searchFilter);
                string ldapFilter = String.Format("(&(objectClass=user)({0}={1}))", attributeName, searchFilter);
                logger.Debug("Ldap filter:" + ldapFilter);
                string[] attributes = { "sAMAccountName" };
                SearchRequest searchRequest = new SearchRequest(scope, ldapFilter, System.DirectoryServices.Protocols.SearchScope.Subtree, attributes);
                SearchResponse response = (SearchResponse)ldapConn.SendRequest(searchRequest);

                if (response != null && response.Entries.Count > 0) {
                    samAccountName = response.Entries[0].Attributes["sAMAccountName"][0].ToString();
                } else {
                    logger.Info("No account matching " + searchFilter + " found");
                }
            } catch (Exception ex) {
                logger.Error("Error while searching account " + searchFilter + ": " + ex.ToString());
            } finally {
                ldapConn.Dispose();
            }

            return samAccountName;
        }

        public static string FindAdGroupLdap(LdapConnection ldapConn, string searchFilter, string attributeName, string scope)
        {
            string samAccountName = null;

            if (ldapConn != null) {
                try {
                    logger.Info("Searching group " + searchFilter);
                    string ldapFilter = String.Format("(&(objectClass=group)(sAMAccountName={0}))", searchFilter);

                    //logger.Debug("Ldap filter:" + ldapFilter);
                    logger.Debug(String.Format("Ldap filter: {0}", ldapFilter));
                    string[] attributes = { attributeName };
                    SearchRequest searchRequest = new SearchRequest(scope, ldapFilter, System.DirectoryServices.Protocols.SearchScope.Subtree, attributes);
                    SearchResponse response = (SearchResponse)ldapConn.SendRequest(searchRequest);
                    if (response != null && response.Entries.Count > 0) {
                        samAccountName = response.Entries[0].Attributes[attributeName][0].ToString();
                    } else {
                        logger.Info("No group matching " + searchFilter + " found");
                    }
                }
                catch (Exception ex) {
                    logger.Error("Error while searching group " + searchFilter + ": " + ex.ToString());
                }
                //finally
                //{
                //    ldapConn.Dispose();
                //}
                
            }
            return samAccountName;
        }

        public static ServerResponse CreateSafeV2(string sessionToken, string safeName, string managingCPM, string description, bool oLACEnabled, int numberOfDaysRetention)
        {
            string create_safe_endpoint = "/PasswordVault/API/Safes";
            JObject payload = new JObject(
                new JProperty("safeName", safeName),
                new JProperty("managingCPM", managingCPM), 
                new JProperty("description", description), 
                new JProperty("oLACEnabled", oLACEnabled), 
                new JProperty("numberOfDaysRetention", numberOfDaysRetention)
                //new JProperty("numberOfVersionsRetention", null),
                //new JProperty("location", "")
                );

            logger.Info(String.Format("--> Create safe {0}", safeName));
            logger.Debug(String.Format("Create safe Payload = {0}", payload.ToString()));
            ServerResponse serverResponse = CFNUtils.SendHttpRequest(sessionToken, "POST", create_safe_endpoint, payload.ToString());
            return serverResponse;
        }

    }
}
