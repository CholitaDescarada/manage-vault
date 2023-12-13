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
using System.Net;
using CyberArk.AIM.NetPasswordSDK;
using CyberArk.AIM.NetPasswordSDK.Exceptions;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace manageVault
{
    using CfnUtils;
    public partial class ResetProv : System.Web.UI.Page
    {
        protected static readonly log4net.ILog logger = log4net.LogManager.GetLogger("ResetProv");

        protected void Page_Load(object sender, EventArgs e)
        {
            if (!Page.IsPostBack)
            {
                log4net.Config.XmlConfigurator.Configure();
            }
        }

        protected void btnReset_Click(object sender, EventArgs e)
        {
            ServicePointManager.ServerCertificateValidationCallback += (o, c, ch, er) => true;

            string password = null;
            try {
                logger.Info("--> Fetch " + CFNUtils.vault_user + " password");
                password = CFNUtils.AIMGetPassword(CFNUtils.vault_user_safe_name, CFNUtils.app_id, CFNUtils.vault_user_object_name);
                logger.Info("  -> password fetched");
            } catch (PSDKException ex) {
                AddErrorMessage("ERROR : Impossible de récuperer le mot de passe du compte  " + CFNUtils.vault_user + " :" + ex.Reason);
                return;
            }

            string session_token = CFNUtils.LogonVault(CFNUtils.vault_user, password);
            if (session_token == null) {
                AddErrorMessage("ERROR : Unable to get session token : ");
                return;
            }

            //string[] providers = ProvidersText.Text.Split(';');
            string[] providers = Regex.Split(ProvidersText.Text, "[;,]");
            bool allOk = true;
            foreach (string serverName in providers) {
                string provName = "";
                if (serverName.StartsWith("Prov_") || serverName.StartsWith("PROV_")) {
                    provName = serverName;
                } else {
                    provName = GetProviderUserName(serverName);
                }

                //string payload = "{\"NewPassword\":\"2mtPx0Q45WqDKK0\"}";
                string payload = (new JObject(new JProperty("NewPassword", "2mtPx0Q45WqDKK0"))).ToString(Formatting.None);
                
                string update_user_endpoint = "/PasswordVault/WebServices/PIMServices.svc/Users/" + provName;
                logger.Info("Reset password of user " + provName);

                CFNUtils.ServerResponse serverResponse = CFNUtils.SendHttpRequest(session_token, "PUT", update_user_endpoint, payload);

                if (CFNUtils.IsFailure(serverResponse)) {
                    AddErrorMessage("Reset password for user " + provName + " failed, check logs for more details.");
                    allOk = false;
                }
                //payload = "{\"Suspended\":false}";
                payload = (new JObject(new JProperty("Suspended", "false"))).ToString(Formatting.None);
                logger.Info("Unlock user " + provName);
                serverResponse = CFNUtils.SendHttpRequest(session_token, "PUT", update_user_endpoint, payload);

                if (CFNUtils.IsFailure(serverResponse)) {
                    AddErrorMessage("Unlock user " + provName + " failed, check logs for more details.");
                    allOk = false;
                }
            }

            CFNUtils.LogoffVault(session_token);
            if (allOk) {
                infosLabel.Text += "All provider users password reset";
            }
        }

        private void AddErrorMessage(string message)
        {

            ((SiteMaster)(this.Master)).publishError(message);
        }

        private string GetProviderUserName(string serverName)
        {
            if (CFNUtils.IsProdEnv() && (serverName.StartsWith("DK") || serverName.StartsWith("LP")))
            {
                return "Prov_ROBOT_" + serverName;
            }
            else
            {
                return "Prov_" + serverName;
            }

        }


    }
}
