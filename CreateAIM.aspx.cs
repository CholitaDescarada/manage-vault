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
//using System.Collection.Generics;

namespace manageVault
{
    using CfnUtils;
    public partial class CreateAIM : System.Web.UI.Page
    {
        // Current logger
        protected static readonly log4net.ILog logger = log4net.LogManager.GetLogger("CreateAIM");

        protected void Page_Load(object sender, EventArgs e)
        {
            if (!Page.IsPostBack)
            {
                log4net.Config.XmlConfigurator.Configure();
            }

        }

 

        protected void codeIUA_ServerValidate(object source, ServerValidateEventArgs e) {
            RegexStringValidator regex = new RegexStringValidator(@"^[a-zA-Z0-9]{3}$");
            // e.IsValid = e.Value.Length == 3
            try {
                regex.Validate(e.Value);
                e.IsValid = true;
            }
            catch (ArgumentException) {
                e.IsValid = false;
            }
        }

        protected void appDesc_ServerValidate(object source, ServerValidateEventArgs e) {
            RegexStringValidator regex = new RegexStringValidator(@"^[0-9A-Za-z!#$%()*+,-./:;=?@\[\\\]\^_`{|}~ ]+$");
            try {
                regex.Validate(e.Value);
                e.IsValid = true;
            }
            catch (ArgumentException) {
                e.IsValid = false;
            }
        }

        protected void providers_ServerValidate(object source, ServerValidateEventArgs e) {
            RegexStringValidator regex = new RegexStringValidator(@"^[a-zA-Z0-9,; _\-]+$");
            try {
                regex.Validate(e.Value);
                e.IsValid = true;
            }
            catch (ArgumentException) {
                e.IsValid = false;
            }
        }

        protected void osUsers_ServerValidate(object source, ServerValidateEventArgs e) {
            RegexStringValidator regex = new RegexStringValidator(@"^[a-zA-Z0-9,;_ \-\\]+$");
            try {
                regex.Validate(e.Value);
                e.IsValid = true;
            }
            catch (ArgumentException) {
                e.IsValid = false;
            }
        }

        protected void paths_ServerValidate(object source, ServerValidateEventArgs e) {
            RegexStringValidator regex = new RegexStringValidator(@"^[^<]+$");
            try {
                regex.Validate(e.Value);
                e.IsValid = true;
            }
            catch (ArgumentException) {
                e.IsValid = false;
            }
        }

        protected void btnCreate_Click(object sender, EventArgs e)
        {
            if (Page.IsValid)
            {
                ServicePointManager.ServerCertificateValidationCallback += (o, c, ch, er) => true;

                // Clear labels
                infosLabel.Text = "";
                infosLabel.TextMode = TextBoxMode.MultiLine;
                infosLabel.Rows = 3;

                // **************************************************
                logger.Info("-------------- Start creation process --------------");

                string password = null;
                bool removeCreateUser = false;
                string cpmName = CFNUtils.password_manager;

                try {
                    //logger.Info("--> Fetch " + CFNUtils.vault_user + "  password");
                    logger.Info(String.Format("--> Fetch {0} password", CFNUtils.vault_user));

                    password = CFNUtils.AIMGetPassword(CFNUtils.vault_user_safe_name, CFNUtils.app_id, CFNUtils.vault_user_object_name);
                    logger.Info("  -> password fetched");
                }
                catch (PSDKException ex) {
                    //AddErrorMessage("ERROR: Failed to get password of user " + CFNUtils.vault_user + ": " + ex.Reason);
                    AddErrorMessage(String.Format("ERROR: Failed to get password for user {0}: {1}", CFNUtils.vault_user, ex.Reason));

                    logger.Error(ex);
                    return;
                }

                string session_token = CFNUtils.LogonVault(CFNUtils.vault_user, password);
                if (session_token == null) {
                    AddErrorMessage("ERROR: Unable to get session token");
                    return;
                }

                string iuaCode = codeIUA.Text.ToUpper();

                //Si le paramètre SafeNamePrefix n'existe pas, le préfixe par défaut d'un coffre est CF.
                string safeNamePrefix = String.IsNullOrEmpty(ConfigurationManager.AppSettings["SafeNamePrefix"]) ? "CF" : ConfigurationManager.AppSettings["SafeNamePrefix"];
                
                string safeName = String.Format("{0}-AIM-{1}", safeNamePrefix, iuaCode);

                string appID = null;

                //string cleanAppDesc = CFNUtils.CleanString(appDesc.Text);
                //Verificator permet de garder une description propre
                //string cleanAppDesc = appDesc.Text;
                string cleanAppDesc = String.Format("{0}", CFNUtils.CleanString(appDesc.Text));

                //Separateurs acceptés dans les formulaires
                char[] separators = new char[] { ';', ',', ' ' };

                string[] providers = providerName.Text.Split(separators, StringSplitOptions.RemoveEmptyEntries);

                bool safeAlreadyExists = true;
                bool appAlreadyExists = false;
                bool updateMode = false;
                List<string> safeMembers = new List<string>();

                // **************** get safe *********************
                string get_safe_details_endpoint = String.Format("/PasswordVault/WebServices/PIMServices.svc/Safes/{0}", safeName);
                logger.Info(String.Format("--> Check safe {0} existence", safeName));

                CFNUtils.ServerResponse serverResponse = CFNUtils.SendHttpRequest(session_token, "GET", get_safe_details_endpoint, "");
                if (serverResponse.cyberarkError != null && serverResponse.cyberarkError.ErrorMessage.Contains("does not exist")) {
                    logger.Info(String.Format("Safe {0} does not exist -> Create it", safeName));
                    safeAlreadyExists = false;
                } else if (CFNUtils.IsFailure(serverResponse)) {
                    AddErrorMessage(String.Format("Error occurred while trying to get details of safe {0}, check logs for more details. Execution aborted.", safeName));
                    logger.Info("Execution aborted");
                    return;
                } else {
                    logger.Info(String.Format("Safe {0} already exists", safeName));
                    updateMode = true;
                }

                
                if (!safeAlreadyExists) {
                    // **************** create safe *********************
                   /* string create_safe_endpoint = "/PasswordVault/WebServices/PIMServices.svc/Safes";
                    JObject payload = new JObject(new JProperty("safe", new JObject(new JProperty("SafeName", safeName), new JProperty("ManagingCPM", cpmName), new JProperty("Description", cleanAppDesc), new JProperty("OLACEnabled", false), new JProperty("NumberOfDaysRetention", 7))));

                    logger.Info(String.Format("--> Create safe {0}", safeName));
                    serverResponse = CFNUtils.SendHttpRequest(session_token, "POST", create_safe_endpoint, payload.ToString());
                    */
                    serverResponse = CFNUtils.CreateSafeV2(session_token, safeName, cpmName, cleanAppDesc, false, 7);

                    if (CFNUtils.IsFailure(serverResponse)) {
                        AddErrorMessage(String.Format("Creation of safe {0} failed, check logs for more details. Execution aborted.", safeName));
                        logger.Info("Execution aborted");
                        return;
                    }
                } else {
                    // **************** get safe members *********************
                    string get_safe_members_endpoint = String.Format("/PasswordVault/WebServices/PIMServices.svc/Safes/{0}/Members", safeName);
                    logger.Info(String.Format("--> Get members of safe {0}", safeName));
                    serverResponse = CFNUtils.SendHttpRequest(session_token, "GET", get_safe_members_endpoint, "");

                    if (CFNUtils.IsFailure(serverResponse)) {
                        //AddErrorMessage("Getting members of " + safeName + " failed, check logs for more details. Execution aborted.");
                        AddErrorMessage(String.Format("Getting members of {0} failed, check logs for more details. Execution aborted.", safeName));
                        logger.Info("Execution aborted");
                        return;
                    } else {
                        string response = serverResponse.response;
                        try {
                            Dictionary<String, List<Dictionary<String, Object>>> data = JsonConvert.DeserializeObject<Dictionary<String, List<Dictionary<String, Object>>>>(response);
                            foreach (Dictionary<String, Object> member in data["members"]) {
                                string username = (string)member["UserName"];
                                if (username.StartsWith("APP_") || username.StartsWith("APP-")) {
                                    appID = username;
                                    appAlreadyExists = true;
                                }

                                logger.Debug("Found member " + username);
                                safeMembers.Add(username);
                            }
                        }
                        catch (JsonSerializationException ex) {
                            logger.Error("Failed to parse CyberArk response: " + ex.Message);
                            AddErrorMessage("Failed to parse Get safe members response, check logs for more details. Execution aborted.");
                            logger.Info("Execution aborted");
                            return;
                        }
                    }
                }

                if (!appAlreadyExists) {
                    // **************** Create application *********************
                    appID = CFNUtils.IsProdEnv() ? String.Format("APP_{0}", iuaCode) : String.Format("APP_HP_{0}", iuaCode);
                    string create_app_endpoint = "/PasswordVault/WebServices/PIMServices.svc/Applications/";
                    JObject payload = new JObject(new JProperty("application", new JObject(new JProperty("AppID", appID), new JProperty("Description", cleanAppDesc))));

                    logger.Info(String.Format("--> Creating application {0}", appID));
                    serverResponse = CFNUtils.SendHttpRequest(session_token, "POST", create_app_endpoint, payload.ToString());

                    if (CFNUtils.IsFailure(serverResponse)) {
                        AddErrorMessage(String.Format("Creation of application {0} failed, check logs for more details. Execution aborted.", appID));
                        logger.Info(String.Format("Creation of application {0} failed. Execution aborted.", appID));
                        return;
                    }
                }
                else {logger.Info(String.Format("Found already existing application for this safe: {0}", appID));}

                // **************** Add authentication methods *********************
                bool windowsServerContext = IsWindowsServerContext(providers);
                string add_auth_endpoint = String.Format("/PasswordVault/WebServices/PIMServices.svc/Applications/{0}/Authentications", appID);
                
                // add machineAddress authentication methods
                logger.Info("--> Adding machineAddress authentication methods and create provider users");
                if (!String.IsNullOrEmpty(providerName.Text)) {
                    foreach (string provider in providers) {
                        string serverName = provider.Trim();
                        if (serverName.StartsWith("Prov_", StringComparison.OrdinalIgnoreCase)) {serverName = serverName.Replace("Prov_", "");}

                        if (! safeMembers.Contains(GetProviderUserName(serverName))) {
                            JObject payload = new JObject(new JProperty("authentication", new JObject(new JProperty("AuthType", "machineAddress"), new JProperty("AuthValue", serverName))));

                            logger.Info(String.Format("  -> Add machine address auth method for host {0}", serverName));
                            serverResponse = CFNUtils.SendHttpRequest(session_token, "POST", add_auth_endpoint, payload.ToString());

                            if (CFNUtils.IsFailure(serverResponse)) {AddErrorMessage(String.Format("Error while adding machineAddess auth method for server {0}", serverName));}
                        }
                    }
                }

                // add osUser authentication methods
                logger.Info("--> Adding osUser authentication methods");
                if (!String.IsNullOrEmpty(osUsers.Text)) {
                    foreach (string osUser in osUsers.Text.Split(separators, StringSplitOptions.RemoveEmptyEntries)) {
                        string account = osUser.Trim();

                        if (windowsServerContext && !osUser.StartsWith(@"CIB\", StringComparison.OrdinalIgnoreCase)) { CreateApposUser(session_token, @"CIB\" + account, add_auth_endpoint); }
                        else { CreateApposUser(session_token, account.Replace("cib", "CIB"), add_auth_endpoint); }
                    }
                }

                // add path authentication methods
                //Les espaces sont autorisés dans les chemins, donc il faut redéfinir les séparateurs
                separators = new char[] { ';', ',' };
                logger.Info("--> Adding path authentication methods");
                if (!String.IsNullOrEmpty(paths.Text)) {
                    foreach (string path in paths.Text.Split(separators, StringSplitOptions.RemoveEmptyEntries)) {
                        //Création du payload en fonction des critères cochés
                        JObject payload = CreateApppathPayload(pathIsFolder.Checked, allowInternalScripts.Checked, path);

                        logger.Info(String.Format("  -> Adding path authentication method for path {0}", path));
                        logger.Debug(String.Format(" payload: {0}", payload.ToString(Formatting.None)));
                        serverResponse = CFNUtils.SendHttpRequest(session_token, "POST", add_auth_endpoint, payload.ToString(Formatting.None));

                        if (CFNUtils.IsFailure(serverResponse)) { AddErrorMessage(String.Format("Error while adding path auth method for path {0}", path)); }
                    }
                }

                // **************** create provider users ***********
                string create_user_endpoint = "/PasswordVault/WebServices/PIMServices.svc/Users";
                string add_user_to_group_endpoint = "/PasswordVault/WebServices/PIMServices.svc/Groups/Providers/Users";
                logger.Info("--> Create provider users");
                if (!String.IsNullOrEmpty(providerName.Text)) {
                    foreach (string serverName in providers) {
                        string provName = GetProviderUserName(serverName);
                        if (!safeMembers.Contains(provName)) {
                            string create_user_payload = (JsonConvert.SerializeObject(new ProviderUser(provName)));
                            logger.Info(String.Format("  -> Create provider user {0}", provName));

                            serverResponse = CFNUtils.SendHttpRequest(session_token, "POST", create_user_endpoint, create_user_payload);
                            if (serverResponse.cyberarkError != null && serverResponse.cyberarkError.ErrorMessage.Contains("has already been defined")) { logger.Info(String.Format("User {0} already exists", provName)); }
                            else if (CFNUtils.IsFailure(serverResponse)) {
                                AddErrorMessage(String.Format("Failed to create provider user {0}, check logs for more details. Execution aborted", provName));
                                return;
                            } else { logger.Info(String.Format("Provider user {0} created", provName)); }

                            //************ add user to Providers group ***********
                            string add_user_to_group_payload = "{\"UserName\": \"" + provName + "\"}";
                            logger.Info(String.Format("  -> Add provider user {0} to Providers group", provName));
                            serverResponse = CFNUtils.SendHttpRequest(session_token, "POST", add_user_to_group_endpoint, add_user_to_group_payload);

                            if (serverResponse.cyberarkError != null && serverResponse.cyberarkError.ErrorMessage.Contains("already")) { logger.Info(String.Format("User {0} already members of Providers group", provName)); }
                            else if (CFNUtils.IsFailure(serverResponse)) {
                                AddErrorMessage(String.Format("Failed to add provider user {0} to Providers group, check logs for more details. Execution aborted", provName));
                                return;
                            } else { logger.Info(String.Format("Provider user {0} added to Providers group", provName)); }
                        }
                        else { logger.Info(String.Format("Provider user {0} is already member of this safe", provName)); }
                    }
                }

                // **************** add members *********************
                bool createWithPacli = false;
                var update_safe_member_endpoint = String.Format("/PasswordVault/WebServices/PIMServices.svc/Safes/{0}/Members/", safeName);

                NameValueCollection membersToAdd = new NameValueCollection();
                //string managerGroup = "G_" + safeName.Replace(' ', '-') + "-" + appID.Replace(' ', '-') + "_Gst";
                //string userGroup = "G_" + safeName.Replace(' ', '-') + "-" + appID.Replace(' ', '-') + "_Usr";
                string managerGroup = String.Format("G_{0}-{1}_Gst", safeName, appID);
                string userGroup =    String.Format("G_{0}-{1}_Usr", safeName, appID);
                string g_full_admin = CFNUtils.g_full_admin;
                string IdentityIQ = CFNUtils.IsProdEnv() ? ConfigurationManager.AppSettings["IdentityIQ_PROD"] : ConfigurationManager.AppSettings["IdentityIQ_QUA"];
                string CloudProvisioningTools = String.IsNullOrEmpty(ConfigurationManager.AppSettings["CloudProvisioningTools"]) ? "G_CFN_CloudProvisioningTools_Prod" : ConfigurationManager.AppSettings["CloudProvisioningTools"];

                if (!updateMode) {
                    String payload;

                    Dictionary<string, object> g_full_adminRights = new Dictionary<string, object>() {
                        {"UseAccounts", true},
                        {"RetrieveAccounts", true},
                        {"ListAccounts", true},
                        {"AddAccounts", true},
                        {"UpdateAccountContent", true},
                        {"UpdateAccountProperties", true},
                        {"InitiateCPMAccountManagementOperations", true},
                        {"SpecifyNextAccountContent", true},
                        {"RenameAccounts", true},
                        {"DeleteAccounts", true},
                        {"UnlockAccounts", true},
                        {"ManageSafe", true},
                        {"ManageSafeMembers", true},
                        {"BackupSafe", true},
                        {"ViewAuditLog", true},
                        {"ViewSafeMembers", true},
                        {"RequestsAuthorizationLevel", 1},
                        {"AccessWithoutConfirmation", true},
                        {"CreateFolders", true},
                        {"DeleteFolders", true},
                        {"MoveAccountsAndFolders", true}
                    };

                    payload = GetMemberPayload(g_full_admin, "Vault", g_full_adminRights);
                    membersToAdd.Add(g_full_admin, payload);

                    Dictionary<string, object> IdentityIQRights = new Dictionary<string, object>() {
                        {"UseAccounts", false},
                        {"RetrieveAccounts", false},
                        {"ListAccounts", true},
                        {"AddAccounts", true},
                        {"UpdateAccountContent", false},
                        {"UpdateAccountProperties", true},
                        {"InitiateCPMAccountManagementOperations", false},
                        {"SpecifyNextAccountContent", false},
                        {"RenameAccounts", false},
                        {"DeleteAccounts", false},
                        {"UnlockAccounts", false},
                        {"ManageSafe", false},
                        {"ManageSafeMembers", false},
                        {"BackupSafe", false},
                        {"ViewAuditLog", false},
                        {"ViewSafeMembers", false},
                        {"RequestsAuthorizationLevel", 0},
                        {"AccessWithoutConfirmation", false},
                        {"CreateFolders", false},
                        {"DeleteFolders", false},
                        {"MoveAccountsAndFolders", false}
                    };

                    payload = GetMemberPayload(IdentityIQ, "ADCIB", IdentityIQRights);
                    membersToAdd.Add(IdentityIQ, payload);
                    //membersToAdd.Add(IdentityIQ, "{\"member\":{\"MemberName\":\"" + IdentityIQ + "\" , \"SearchIn\":\"ADCIB\",\"MembershipExpirationDate\":\"\",\"Permissions\":[{\"Key\":\"UseAccounts\", \"Value\":false},{\"Key\":\"RetrieveAccounts\", \"Value\":false},{\"Key\":\"ListAccounts\", \"Value\":true},{\"Key\":\"AddAccounts\", \"Value\":true},{\"Key\":\"UpdateAccountContent\",\"Value\":false},{\"Key\":\"UpdateAccountProperties\",\"Value\":true},{\"Key\":\"InitiateCPMAccountManagementOperations\",\"Value\":false},{\"Key\":\"SpecifyNextAccountContent\",\"Value\":false},{\"Key\":\"RenameAccounts\", \"Value\":false},{\"Key\":\"DeleteAccounts\", \"Value\":false},{\"Key\":\"UnlockAccounts\", \"Value\":false},{\"Key\":\"ManageSafe\", \"Value\":false},{\"Key\":\"ManageSafeMembers\", \"Value\":false},{\"Key\":\"BackupSafe\", \"Value\":false},{\"Key\":\"ViewAuditLog\", \"Value\":false},{\"Key\":\"ViewSafeMembers\", \"Value\":false},{\"Key\":\"RequestsAuthorizationLevel\",\"Value\":0},{\"Key\":\"AccessWithoutConfirmation\",\"Value\":false},{\"Key\":\"CreateFolders\", \"Value\":false},{\"Key\":\"DeleteFolders\", \"Value\":false},{\"Key\":\"MoveAccountsAndFolders\",\"Value\":false}]}}");

                    membersToAdd.Add(CloudProvisioningTools, "{\"member\":{\"MemberName\": \"" + CloudProvisioningTools + "\", \"SearchIn\":\"ADCIB\",\"MembershipExpirationDate\":\"\",\"Permissions\":[{\"Key\":\"UseAccounts\", \"Value\":false},{\"Key\":\"RetrieveAccounts\", \"Value\":false},{\"Key\":\"ListAccounts\", \"Value\":true},{\"Key\":\"AddAccounts\", \"Value\":true},{\"Key\":\"UpdateAccountContent\",\"Value\":false},{\"Key\":\"UpdateAccountProperties\",\"Value\":true},{\"Key\":\"InitiateCPMAccountManagementOperations\",\"Value\":false},{\"Key\":\"SpecifyNextAccountContent\",\"Value\":false},{\"Key\":\"RenameAccounts\", \"Value\":false},{\"Key\":\"DeleteAccounts\", \"Value\":false},{\"Key\":\"UnlockAccounts\", \"Value\":false},{\"Key\":\"ManageSafe\", \"Value\":false},{\"Key\":\"ManageSafeMembers\", \"Value\":false},{\"Key\":\"BackupSafe\", \"Value\":false},{\"Key\":\"ViewAuditLog\", \"Value\":false},{\"Key\":\"ViewSafeMembers\", \"Value\":false},{\"Key\":\"RequestsAuthorizationLevel\",\"Value\":0},{\"Key\":\"AccessWithoutConfirmation\",\"Value\":false},{\"Key\":\"CreateFolders\", \"Value\":false},{\"Key\":\"DeleteFolders\", \"Value\":false},{\"Key\":\"MoveAccountsAndFolders\",\"Value\":false}]}}");
                    membersToAdd.Add(cpmName, "{\"member\":{\"MemberName\": \"" + cpmName + "\", \"SearchIn\":\"Vault\",\"MembershipExpirationDate\":\"\",\"Permissions\":[{\"Key\":\"UseAccounts\", \"Value\":true},{\"Key\":\"RetrieveAccounts\", \"Value\":true},{\"Key\":\"ListAccounts\", \"Value\":true},{\"Key\":\"AddAccounts\", \"Value\":true},{\"Key\":\"UpdateAccountContent\",\"Value\":true},{\"Key\":\"UpdateAccountProperties\",\"Value\":true},{\"Key\":\"InitiateCPMAccountManagementOperations\",\"Value\":true},{\"Key\":\"SpecifyNextAccountContent\",\"Value\":true},{\"Key\":\"RenameAccounts\", \"Value\":true},{\"Key\":\"DeleteAccounts\", \"Value\":false},{\"Key\":\"UnlockAccounts\", \"Value\":false},{\"Key\":\"ManageSafe\", \"Value\":false},{\"Key\":\"ManageSafeMembers\", \"Value\":false},{\"Key\":\"BackupSafe\", \"Value\":false},{\"Key\":\"ViewAuditLog\", \"Value\":true},{\"Key\":\"ViewSafeMembers\", \"Value\":true},{\"Key\":\"RequestsAuthorizationLevel\",\"Value\":0},{\"Key\":\"AccessWithoutConfirmation\",\"Value\":false},{\"Key\":\"CreateFolders\", \"Value\":true},{\"Key\":\"DeleteFolders\", \"Value\":false},{\"Key\":\"MoveAccountsAndFolders\",\"Value\":true}]}}");
                    membersToAdd.Add(appID, "{\"member\":{\"MemberName\": \"" + appID + "\", \"SearchIn\":\"Vault\",\"MembershipExpirationDate\":\"\",\"Permissions\":[{\"Key\":\"UseAccounts\", \"Value\":true},{\"Key\":\"RetrieveAccounts\", \"Value\":true},{\"Key\":\"ListAccounts\", \"Value\":true},{\"Key\":\"AddAccounts\", \"Value\":false},{\"Key\":\"UpdateAccountContent\",\"Value\":false},{\"Key\":\"UpdateAccountProperties\",\"Value\":false},{\"Key\":\"InitiateCPMAccountManagementOperations\",\"Value\":false},{\"Key\":\"SpecifyNextAccountContent\",\"Value\":false},{\"Key\":\"RenameAccounts\", \"Value\":false},{\"Key\":\"DeleteAccounts\", \"Value\":false},{\"Key\":\"UnlockAccounts\", \"Value\":false},{\"Key\":\"ManageSafe\", \"Value\":false},{\"Key\":\"ManageSafeMembers\", \"Value\":false},{\"Key\":\"BackupSafe\", \"Value\":false},{\"Key\":\"ViewAuditLog\", \"Value\":false},{\"Key\":\"ViewSafeMembers\", \"Value\":false},{\"Key\":\"RequestsAuthorizationLevel\",\"Value\":0},{\"Key\":\"AccessWithoutConfirmation\",\"Value\":false},{\"Key\":\"CreateFolders\", \"Value\":false},{\"Key\":\"DeleteFolders\", \"Value\":false},{\"Key\":\"MoveAccountsAndFolders\",\"Value\":false}]}}");
                    membersToAdd.Add(managerGroup, "{\"member\":{\"MemberName\": \"" + managerGroup + "\", \"SearchIn\":\"ADCIB\",\"MembershipExpirationDate\":\"\",\"Permissions\":[{\"Key\":\"UseAccounts\", \"Value\":true},{\"Key\":\"RetrieveAccounts\", \"Value\":true},{\"Key\":\"ListAccounts\", \"Value\":true},{\"Key\":\"AddAccounts\", \"Value\":true},{\"Key\":\"UpdateAccountContent\",\"Value\":true},{\"Key\":\"UpdateAccountProperties\",\"Value\":true},{\"Key\":\"InitiateCPMAccountManagementOperations\",\"Value\":true},{\"Key\":\"SpecifyNextAccountContent\",\"Value\":true},{\"Key\":\"RenameAccounts\", \"Value\":true},{\"Key\":\"DeleteAccounts\", \"Value\":true},{\"Key\":\"UnlockAccounts\", \"Value\":false},{\"Key\":\"ManageSafe\", \"Value\":false},{\"Key\":\"ManageSafeMembers\", \"Value\":false},{\"Key\":\"BackupSafe\", \"Value\":false},{\"Key\":\"ViewAuditLog\", \"Value\":true},{\"Key\":\"ViewSafeMembers\", \"Value\":true},{\"Key\":\"RequestsAuthorizationLevel\",\"Value\":0},{\"Key\":\"AccessWithoutConfirmation\",\"Value\":false},{\"Key\":\"CreateFolders\", \"Value\":true},{\"Key\":\"DeleteFolders\", \"Value\":true},{\"Key\":\"MoveAccountsAndFolders\",\"Value\":true}]}}");
                    membersToAdd.Add(userGroup, "{\"member\":{\"MemberName\": \"" + userGroup + "\", \"SearchIn\":\"ADCIB\",\"MembershipExpirationDate\":\"\",\"Permissions\":[{\"Key\":\"UseAccounts\", \"Value\":true},{\"Key\":\"RetrieveAccounts\", \"Value\":true},{\"Key\":\"ListAccounts\", \"Value\":true},{\"Key\":\"AddAccounts\", \"Value\":false},{\"Key\":\"UpdateAccountContent\",\"Value\":false},{\"Key\":\"UpdateAccountProperties\",\"Value\":false},{\"Key\":\"InitiateCPMAccountManagementOperations\",\"Value\":false},{\"Key\":\"SpecifyNextAccountContent\",\"Value\":false},{\"Key\":\"RenameAccounts\", \"Value\":false},{\"Key\":\"DeleteAccounts\", \"Value\":false},{\"Key\":\"UnlockAccounts\", \"Value\":false},{\"Key\":\"ManageSafe\", \"Value\":false},{\"Key\":\"ManageSafeMembers\", \"Value\":false},{\"Key\":\"BackupSafe\", \"Value\":false},{\"Key\":\"ViewAuditLog\", \"Value\":true},{\"Key\":\"ViewSafeMembers\", \"Value\":true},{\"Key\":\"RequestsAuthorizationLevel\",\"Value\":0},{\"Key\":\"AccessWithoutConfirmation\",\"Value\":false},{\"Key\":\"CreateFolders\", \"Value\":false},{\"Key\":\"DeleteFolders\", \"Value\":false},{\"Key\":\"MoveAccountsAndFolders\",\"Value\":false}]}}");
                    membersToAdd.Add("EVDGroup", "{\"member\":{\"MemberName\": \"EVDGroup\", \"SearchIn\":\"Vault\",\"MembershipExpirationDate\":\"\",\"Permissions\":[{\"Key\":\"UseAccounts\", \"Value\":false},{\"Key\":\"RetrieveAccounts\", \"Value\":false},{\"Key\":\"ListAccounts\", \"Value\":true},{\"Key\":\"AddAccounts\", \"Value\":false},{\"Key\":\"UpdateAccountContent\",\"Value\":false},{\"Key\":\"UpdateAccountProperties\",\"Value\":false},{\"Key\":\"InitiateCPMAccountManagementOperations\",\"Value\":false},{\"Key\":\"SpecifyNextAccountContent\",\"Value\":false},{\"Key\":\"RenameAccounts\", \"Value\":false},{\"Key\":\"DeleteAccounts\", \"Value\":false},{\"Key\":\"UnlockAccounts\", \"Value\":false},{\"Key\":\"ManageSafe\", \"Value\":false},{\"Key\":\"ManageSafeMembers\", \"Value\":false},{\"Key\":\"BackupSafe\", \"Value\":false},{\"Key\":\"ViewAuditLog\", \"Value\":true},{\"Key\":\"ViewSafeMembers\", \"Value\":true},{\"Key\":\"RequestsAuthorizationLevel\",\"Value\":0},{\"Key\":\"AccessWithoutConfirmation\",\"Value\":false},{\"Key\":\"CreateFolders\", \"Value\":false},{\"Key\":\"DeleteFolders\", \"Value\":false},{\"Key\":\"MoveAccountsAndFolders\",\"Value\":false}]}}");
                }

                // add provider members
                if (!String.IsNullOrEmpty(providerName.Text)) {
                    foreach (string serverName in providers) {
                        string provName = GetProviderUserName(serverName).Trim();
                        if (!safeMembers.Contains(provName)) {
                            membersToAdd.Add(provName, "{\"member\":{\"MemberName\":\"" + provName + "\" , \"SearchIn\":\"Vault\",\"MembershipExpirationDate\":\"\",\"Permissions\":[{\"Key\":\"UseAccounts\", \"Value\":true},{\"Key\":\"RetrieveAccounts\", \"Value\":true},{\"Key\":\"ListAccounts\", \"Value\":true},{\"Key\":\"AddAccounts\", \"Value\":false},{\"Key\":\"UpdateAccountContent\",\"Value\":false},{\"Key\":\"UpdateAccountProperties\",\"Value\":false},{\"Key\":\"InitiateCPMAccountManagementOperations\",\"Value\":false},{\"Key\":\"SpecifyNextAccountContent\",\"Value\":false},{\"Key\":\"RenameAccounts\", \"Value\":false},{\"Key\":\"DeleteAccounts\", \"Value\":false},{\"Key\":\"UnlockAccounts\", \"Value\":false},{\"Key\":\"ManageSafe\", \"Value\":false},{\"Key\":\"ManageSafeMembers\", \"Value\":false},{\"Key\":\"BackupSafe\", \"Value\":false},{\"Key\":\"ViewAuditLog\", \"Value\":true},{\"Key\":\"ViewSafeMembers\", \"Value\":true},{\"Key\":\"RequestsAuthorizationLevel\",\"Value\":0},{\"Key\":\"AccessWithoutConfirmation\",\"Value\":false},{\"Key\":\"CreateFolders\", \"Value\":false},{\"Key\":\"DeleteFolders\", \"Value\":false},{\"Key\":\"MoveAccountsAndFolders\",\"Value\":false}]}}");
                        }
                    }
                }

                String result;
                logger.Info("--> Add members to " + safeName);
                foreach (string member in membersToAdd.AllKeys) {
                    logger.Info("  -> add member " + member);
                    serverResponse = CFNUtils.SendHttpRequest(session_token, "POST", update_safe_member_endpoint, membersToAdd[member]);

                    if (serverResponse.cyberarkError != null && serverResponse.cyberarkError.ErrorMessage.Contains("is already a member")) {
                        logger.Info(String.Format("{0} is already member of this safe", member));
                    } else if (serverResponse.cyberarkError != null && serverResponse.cyberarkError.ErrorMessage.Contains("Input parameter for [MemberName] value is invalid")) {
                        result = String.Format("Member {0} was not found", member);
                        logger.Info(result);

                        //Si ce n'est pas le groupe _Usr, afficher une erreur
                        if (!member.Equals(userGroup)) {
                            AddErrorMessage(result);
                        }
                    } else if (CFNUtils.IsFailure(serverResponse)) {
                        if (member.EndsWith("_Gst")) {
                            createWithPacli = true;
                        } else {
                            AddErrorMessage(String.Format("Failed to add {0} member, check logs for more details", member));
                        }
                        //return;
                    }
                }

                // **************** Remove CreateUser *********************
                if (removeCreateUser) {
                    string createUser = CFNUtils.vault_user;
                    string delete_createUser_endpoint = String.Format("/PasswordVault/WebServices/PIMServices.svc/Safes/{0}/Members/{1}", safeName, createUser);
                    logger.Info(String.Format("--> Remove user {0}", createUser));
                    serverResponse = CFNUtils.SendHttpRequest(session_token, "DELETE", delete_createUser_endpoint, "");

                    if (CFNUtils.IsFailure(serverResponse)) {
                        AddErrorMessage(String.Format("Failed to remove user {0}, check logs for more details. Execution aborted.", createUser));
                    }
                }

                // Messages finaux
                string message = appAlreadyExists ? String.Format("The application {0} and the safe {1} were updated successfully", appID, safeName) : String.Format("The application {0} and the safe {1} were created successfully", appID, safeName);
                logger.Info(message);
                AddInfoMessage(message);

                // ************************ Logout ***************************************
                logger.Info("--> Logout from CFN");
                CFNUtils.LogoffVault(session_token);

                // ************************ Add Gst group using PACLI ***************************************
                if (!updateMode && createWithPacli) {
                    //string managerGroupDn = FindManagerGroup(managerGroup);
                    string managerGroupDn = FindManagerGroupLdap(managerGroup);

                    if (managerGroupDn != null) {
                        // run pacli command to onboard Manager AD group
                        logger.Info("--> Add manager group " + managerGroup + " using PACLI");

                        NameValueCollection replacementDict = new NameValueCollection();
                        replacementDict.Add("%GSTGROUPDN%", managerGroupDn);
                        replacementDict.Add("%GSTGROUP%",   managerGroup);
                        replacementDict.Add("%SAFENAME%",   safeName);
                        replacementDict.Add("%VAULTUSER%",  CFNUtils.vault_user);

                        int rc = CFNUtils.RunPacliCmds(Server.MapPath(@"~/App_Data"), "AddAdGroupTemplate.txt", replacementDict);
                        if (rc != 0) {
                            logger.Error(String.Format("PACLI execution returned error code {0}", rc));
                            //AddErrorMessage("Failed to create external group " + managerGroup + ": PACLI execution returned error code " + rc);
                            AddErrorMessage(String.Format("Failed to create external group {0}: PACLI execution returned error code {1}", managerGroup, rc));
                        }
                        //AddManagerGroup(managerGroup, managerGroupDn, safeName);
                    }
                }

                logger.Info("--> Done.");
            }
        }

        private string FindManagerGroupLdap(string managerGroup)
        {
            string ADserver =  ConfigurationManager.AppSettings["ADserver"];
            string ADdomain =  ConfigurationManager.AppSettings["ADdomain"];
            string ADaccount = ConfigurationManager.AppSettings["ADAccount"];
            string ADaccountSafeName = String.IsNullOrEmpty(ConfigurationManager.AppSettings["ADAccountSafeName"]) ? "CF-AIM-W61" : ConfigurationManager.AppSettings["ADAccountSafeName"];
            string ADpassword = null;
            string managerGroupDn = null;

            try {
                logger.Debug("--> Request AD CIB browsing account password...");
                ADpassword = CFNUtils.AIMGetPassword(ADaccountSafeName, CFNUtils.app_id, ConfigurationManager.AppSettings["ADAccountObjectName"]);
            }
            catch (PSDKException ex) {
                AddErrorMessage("ERROR: Failed to get password of CIB browsing account: " + ex.Reason);
                return null;
            }

            LdapConnection ldapConn = CFNUtils.LdapConnectAD(ADserver, ADdomain, ADaccount, ADpassword);
            if (ldapConn != null) {
                managerGroupDn = CFNUtils.FindAdGroupLdap(ldapConn, managerGroup, "DistinguishedName", "OU=Groups,OU=_EMEA-FR,DC=cib,DC=net");
            }
            return managerGroupDn;

        }

        private string FindManagerGroup(string managerGroup)
        {
            // Querying Active Directory
            System.Security.Principal.WindowsImpersonationContext impersonationContext;
            impersonationContext = ((System.Security.Principal.WindowsIdentity)User.Identity).Impersonate();

            //Récupération des variables depuis le fichier de configuration
            string ADserver =  ConfigurationManager.AppSettings["ADserver"];
            string ADdomain =  ConfigurationManager.AppSettings["ADdomain"];
            string ADaccount = ConfigurationManager.AppSettings["ADAccount"];
            string ADaccountSafeName = String.IsNullOrEmpty(ConfigurationManager.AppSettings["ADAccountSafeName"]) ? "CF-AIM-W61" : ConfigurationManager.AppSettings["ADAccountSafeName"];
            string ADpassword = null;
            string managerGroupDn = null;

            try {
                logger.Debug("--> Request AD CIB browsing account password...");
                ADpassword = CFNUtils.AIMGetPassword(ADaccountSafeName, CFNUtils.app_id, ConfigurationManager.AppSettings["ADAccountObjectName"]); 
            }
            catch (PSDKException ex) {
                AddErrorMessage("ERROR: Failed to get password of CIB browsing account: " + ex.Reason);
                return null;
            }

            PrincipalContext ctx = null; // = new PrincipalContext(ContextType.Domain, ADserver, ADdomain, ADaccount, ADpassword);

            try {
                if (CFNUtils.useSSL) {
                    ADserver = ADserver + ":636";
                    ContextOptions options = ContextOptions.SimpleBind | ContextOptions.SecureSocketLayer;
                    ctx = new PrincipalContext(ContextType.Domain, ADserver, ADdomain, options, ADaccount, ADpassword);
                }
                else {
                    ctx = new PrincipalContext(ContextType.Domain, ADserver, ADdomain, ADaccount, ADpassword);
                }
                PrincipalSearcher srch = new PrincipalSearcher(new GroupPrincipal(ctx, managerGroup));
                logger.Debug("--> Searching group " + managerGroup);
                Principal principal = srch.FindOne();

                if (principal == null) {
                    logger.Error("Unable to find group " + managerGroup);
                    AddErrorMessage("Unable to find group " + managerGroup);
                }
                else {
                    managerGroupDn = principal.DistinguishedName;
                }
            }
            catch (Exception e) {
                logger.Error("Failed to search manager group in AD: " + e.Message);
                AddErrorMessage("Failed to search manager group in AD: " + e.Message);
            }
            finally {
                impersonationContext.Undo();
            }
            return managerGroupDn;
        }


        private string GetProviderUserName(string serverName) {
            serverName = serverName.Trim();
            if (!serverName.StartsWith("Prov_", StringComparison.OrdinalIgnoreCase)) {
                if (serverName.StartsWith("DK") || serverName.StartsWith("LP")) {
                    return "Prov_ROBOT_" + serverName;
                } else {
                    return "Prov_" + serverName;
                }
            } else {
                return serverName;
            }

        }


        private string GetMemberPayload(string userName, string searchIn, Dictionary<string, object> rights) {
            List<JObject> rightsList = new List<JObject>();
            foreach (KeyValuePair<string, object> ele2 in rights) {
                rightsList.Add(new JObject(new JProperty("Key", ele2.Key), new JProperty("Value", ele2.Value)));
            }

            JObject payload = new JObject(new JProperty("member", new JObject(
                new JProperty("MemberName", userName),
                new JProperty("SearchIn", searchIn),
                new JProperty("MembershipExpirationDate", ""),
                new JProperty("Permissions", rightsList))));

            logger.Info(String.Format("Test de payload : {0}", payload.ToString(Formatting.None)));

            return payload.ToString(Formatting.None);
        }


        private bool IsWindowsServerContext(string[] servers) {
            //A partir du moment où un serveur ne commence pas par "sw", alors le contexte n'est pas Windows
            foreach (string server in servers) {
                if (!IsWindowsServer(server)) {
                    return false;
                }
            }
            return true;
        }

        private bool IsWindowsServer(string serverName) {
            return serverName.StartsWith("sw", StringComparison.OrdinalIgnoreCase);
        }

        private void CreateApposUser(string session_token, string accountName, string auth_endpoint) {
            logger.Info(String.Format("  -> Adding osUser authentication method for account {0}", accountName));
            JObject payload = new JObject(new JProperty("authentication", new JObject(new JProperty("AuthType", "osUser"), new JProperty("AuthValue", accountName))));

            CFNUtils.ServerResponse serverResponse = CFNUtils.SendHttpRequest(session_token, "POST", auth_endpoint, payload.ToString());
            if (CFNUtils.IsFailure(serverResponse)) { AddErrorMessage(String.Format("Error while adding osUser auth method for user {0}", accountName)); }
        }

        private JObject CreateApppathPayload(bool IsFolder, bool AllowInternalScripts, string path) {
            JObject payload;

            if (IsFolder && AllowInternalScripts) { payload = new JObject(new JProperty("authentication", new JObject(new JProperty("AuthType", "path"), new JProperty("AuthValue", path), new JProperty("IsFolder", IsFolder), new JProperty("AllowInternalScripts", AllowInternalScripts)))); }
            else if (IsFolder)                    { payload = new JObject(new JProperty("authentication", new JObject(new JProperty("AuthType", "path"), new JProperty("AuthValue", path), new JProperty("IsFolder", IsFolder)))); }
            else if (AllowInternalScripts)        { payload = new JObject(new JProperty("authentication", new JObject(new JProperty("AuthType", "path"), new JProperty("AuthValue", path), new JProperty("AllowInternalScripts", AllowInternalScripts)))); }
            else                                  { payload = new JObject(new JProperty("authentication", new JObject(new JProperty("AuthType", "path"), new JProperty("AuthValue", path)))); }

            return payload;
        }

        private void AddErrorMessage(string message) {
            //infosLabel.ForeColor = System.Drawing.Color.Red;
            //infosLabel.Text += message + System.Environment.NewLine;
            ((SiteMaster)(this.Master)).publishError(message);
        }

        private void AddInfoMessage(string message) { infosLabel.Text += message + System.Environment.NewLine; }

        class ProviderUser {
            public string UserName;
            public string InitialPassword = "2mtPx0Q45WqDKK0";
            public string UserTypeName = "AppProvider";
            public string Location = @"\" + "Applications";
            public bool ChangePasswordOnTheNextLogon = false;

            public ProviderUser(string username) { this.UserName = username; }
        }

        
    }


}
