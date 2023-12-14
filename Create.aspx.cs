using System;
using System.Collections.Generic;
using System.Collections.Specialized;
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
using System.DirectoryServices.Protocols;

namespace manageVault {
    using CfnUtils;
    public partial class Create : System.Web.UI.Page {
        // Current logger
        protected static readonly log4net.ILog logger = log4net.LogManager.GetLogger("Create");

        protected void Page_Load(object sender, EventArgs e) {
            if (!Page.IsPostBack) {
                log4net.Config.XmlConfigurator.Configure();
                logger.Info("Starting app");
            }
        }

        protected void btnCreate_Click(object sender, EventArgs e) {
            // Clear labels
            infosLabel.Text = "";
            bool removeCreateUser = false;
            bool isMars = safeName.Text.EndsWith("MARS");
            string password = "";

            ServicePointManager.ServerCertificateValidationCallback += (o, c, ch, er) => true;

            // **************************************************

            if (!CFNUtils.IsProdEnv()) {
                infosLabel.Text = "MARS vault are not allowed in Qualification !";
                //return;
            }

            try {
                logger.Info("--> Fetch "+ CFNUtils.vault_user + " password");
                password = CFNUtils.AIMGetPassword(CFNUtils.vault_user_safe_name, CFNUtils.app_id, CFNUtils.vault_user_object_name);
                logger.Info("  -> password fetched");
            } catch (PSDKException ex) {
                AddErrorMessage("ERROR : Impossible de récuperer le mot de passe du compte " + CFNUtils.vault_user +" :" + ex.Reason);
                return;
            }

            string session_token = CFNUtils.LogonVault(CFNUtils.vault_user, password);
            if (session_token == null) {
                AddErrorMessage("ERROR : Unable to get session token : ");
                return;
            }

            string cleanSafeName = CFNUtils.CleanString(safeName.Text);
            //var cleanSafeDescription = CFNUtils.CleanString(safeDescription.Text);
            string cleanSafeDescription = String.Format("{0} (made with ManageVault)", CFNUtils.CleanString(safeDescription.Text));

            // **************** check safe existence *********************
            bool safeAlreadyExists = false;

            //string get_safe_details_endpoint = "/PasswordVault/WebServices/PIMServices.svc/Safes/" + cleanSafeName;
            string get_safe_details_endpoint = String.Format("/PasswordVault/WebServices/PIMServices.svc/Safes/{0}", cleanSafeName);
            logger.Info("--> Check safe " + cleanSafeName + " existence");

            CFNUtils.ServerResponse serverResponse = CFNUtils.SendHttpRequest(session_token, "GET", get_safe_details_endpoint, "");

            if (serverResponse.cyberarkError != null && serverResponse.cyberarkError.ErrorMessage.Contains("does not exist")) {
                logger.Info("Safe " + cleanSafeName + " does not already exist -> Create it");
            } else if (CFNUtils.IsFailure(serverResponse)) {
                AddErrorMessage("Error occurred while trying to get details of safe " + cleanSafeName + ", check logs for more details. Execution aborted.");
                return;
            }  else {
                logger.Info("Safe " + cleanSafeName + " already exists");
                AddErrorMessage("Safe " + cleanSafeName + " already exists !");
                safeAlreadyExists = true;
                //return;
            }
          
            // **************** create safe *********************
            if (!safeAlreadyExists) {
                /*
                logger.Info("--> Create safe " + cleanSafeName);
                string create_safe_endpoint = "/PasswordVault/WebServices/PIMServices.svc/Safes";
                string create_safe_payload = "{\"safe\":{ \"SafeName\":\"" + cleanSafeName + "\", \"Description\":\"" + cleanSafeDescription + "\", \"OLACEnabled\":false, \"NumberOfDaysRetention\":7 }}";
                serverResponse = CFNUtils.SendHttpRequest(session_token, "POST", create_safe_endpoint, create_safe_payload);
                */
                serverResponse = CFNUtils.CreateSafeV2(session_token, cleanSafeName, CFNUtils.password_manager, cleanSafeDescription, false, 7);
                if (CFNUtils.IsFailure(serverResponse)) {
                    AddErrorMessage("Creation of safe " + cleanSafeName + " failed, check logs for more details. Execution aborted.");
                    logger.Info("Execution aborted");
                    return;
                }
            }

            // **************** add members *********************
            bool createGroupsWithPacli = false;
            string update_safe_member_endpoint = String.Format("/PasswordVault/WebServices/PIMServices.svc/Safes/{0}/Members/", cleanSafeName);
            string IdentityIQ = CFNUtils.IsProdEnv() ? ConfigurationManager.AppSettings["IdentityIQ_PROD"] : ConfigurationManager.AppSettings["IdentityIQ_QUA"];

            NameValueCollection membersToAdd = new NameValueCollection();
            membersToAdd.Add(CFNUtils.g_full_admin, "{\"member\":{\"MemberName\": \"" + CFNUtils.g_full_admin + "\" , \"SearchIn\":\"Vault\",\"MembershipExpirationDate\":\"\",\"Permissions\":[{\"Key\":\"UseAccounts\", \"Value\":true},{\"Key\":\"RetrieveAccounts\", \"Value\":true},{\"Key\":\"ListAccounts\", \"Value\":true},{\"Key\":\"AddAccounts\", \"Value\":true},{\"Key\":\"UpdateAccountContent\",\"Value\":true},{\"Key\":\"UpdateAccountProperties\",\"Value\":true},{\"Key\":\"InitiateCPMAccountManagementOperations\",\"Value\":true},{\"Key\":\"SpecifyNextAccountContent\",\"Value\":true},{\"Key\":\"RenameAccounts\", \"Value\":true},{\"Key\":\"DeleteAccounts\", \"Value\":true},{\"Key\":\"UnlockAccounts\", \"Value\":true},{\"Key\":\"ManageSafe\", \"Value\":true},{\"Key\":\"ManageSafeMembers\", \"Value\":true},{\"Key\":\"BackupSafe\", \"Value\":true},{\"Key\":\"ViewAuditLog\", \"Value\":true},{\"Key\":\"ViewSafeMembers\", \"Value\":true},{\"Key\":\"RequestsAuthorizationLevel\",\"Value\":1},{\"Key\":\"AccessWithoutConfirmation\",\"Value\":true},{\"Key\":\"CreateFolders\", \"Value\":true},{\"Key\":\"DeleteFolders\", \"Value\":true},{\"Key\":\"MoveAccountsAndFolders\",\"Value\":true}]}}");
            membersToAdd.Add(IdentityIQ, "{\"member\":{\"MemberName\": \"" + IdentityIQ + "\" , \"SearchIn\":\"ADCIB\",\"MembershipExpirationDate\":\"\",\"Permissions\":[{\"Key\":\"UseAccounts\", \"Value\":false},{\"Key\":\"RetrieveAccounts\", \"Value\":false},{\"Key\":\"ListAccounts\", \"Value\":true},{\"Key\":\"AddAccounts\", \"Value\":true},{\"Key\":\"UpdateAccountContent\",\"Value\":false},{\"Key\":\"UpdateAccountProperties\",\"Value\":true},{\"Key\":\"InitiateCPMAccountManagementOperations\",\"Value\":false},{\"Key\":\"SpecifyNextAccountContent\",\"Value\":false},{\"Key\":\"RenameAccounts\", \"Value\":false},{\"Key\":\"DeleteAccounts\", \"Value\":false},{\"Key\":\"UnlockAccounts\", \"Value\":false},{\"Key\":\"ManageSafe\", \"Value\":false},{\"Key\":\"ManageSafeMembers\", \"Value\":false},{\"Key\":\"BackupSafe\", \"Value\":false},{\"Key\":\"ViewAuditLog\", \"Value\":false},{\"Key\":\"ViewSafeMembers\", \"Value\":false},{\"Key\":\"RequestsAuthorizationLevel\",\"Value\":0},{\"Key\":\"AccessWithoutConfirmation\",\"Value\":false},{\"Key\":\"CreateFolders\", \"Value\":false},{\"Key\":\"DeleteFolders\", \"Value\":false},{\"Key\":\"MoveAccountsAndFolders\",\"Value\":false}]}}");
            membersToAdd.Add(CFNUtils.password_manager, "{\"member\":{\"MemberName\": \"" + CFNUtils.password_manager +"\" , \"SearchIn\":\"Vault\",\"MembershipExpirationDate\":\"\",\"Permissions\":[{\"Key\":\"UseAccounts\", \"Value\":true},{\"Key\":\"RetrieveAccounts\", \"Value\":true},{\"Key\":\"ListAccounts\", \"Value\":true},{\"Key\":\"AddAccounts\", \"Value\":true},{\"Key\":\"UpdateAccountContent\",\"Value\":true},{\"Key\":\"UpdateAccountProperties\",\"Value\":true},{\"Key\":\"InitiateCPMAccountManagementOperations\",\"Value\":true},{\"Key\":\"SpecifyNextAccountContent\",\"Value\":true},{\"Key\":\"RenameAccounts\", \"Value\":true},{\"Key\":\"DeleteAccounts\", \"Value\":false},{\"Key\":\"UnlockAccounts\", \"Value\":true},{\"Key\":\"ManageSafe\", \"Value\":false},{\"Key\":\"ManageSafeMembers\", \"Value\":false},{\"Key\":\"BackupSafe\", \"Value\":false},{\"Key\":\"ViewAuditLog\", \"Value\":true},{\"Key\":\"ViewSafeMembers\", \"Value\":true},{\"Key\":\"RequestsAuthorizationLevel\",\"Value\":0},{\"Key\":\"AccessWithoutConfirmation\",\"Value\":false},{\"Key\":\"CreateFolders\", \"Value\":true},{\"Key\":\"DeleteFolders\", \"Value\":true},{\"Key\":\"MoveAccountsAndFolders\",\"Value\":true}]}}");
            membersToAdd.Add("MassUpload", "{\"member\":{\"MemberName\": \"MassUpload\" , \"SearchIn\":\"Vault\",\"MembershipExpirationDate\":\"\",\"Permissions\":[{\"Key\":\"UseAccounts\", \"Value\":false},{\"Key\":\"RetrieveAccounts\", \"Value\":false},{\"Key\":\"ListAccounts\", \"Value\":true},{\"Key\":\"AddAccounts\", \"Value\":true},{\"Key\":\"UpdateAccountContent\",\"Value\":true},{\"Key\":\"UpdateAccountProperties\",\"Value\":true},{\"Key\":\"InitiateCPMAccountManagementOperations\",\"Value\":true},{\"Key\":\"SpecifyNextAccountContent\",\"Value\":true},{\"Key\":\"RenameAccounts\", \"Value\":true},{\"Key\":\"DeleteAccounts\", \"Value\":false},{\"Key\":\"UnlockAccounts\", \"Value\":true},{\"Key\":\"ManageSafe\", \"Value\":true},{\"Key\":\"ManageSafeMembers\", \"Value\":true},{\"Key\":\"BackupSafe\", \"Value\":false},{\"Key\":\"ViewAuditLog\", \"Value\":true},{\"Key\":\"ViewSafeMembers\", \"Value\":true},{\"Key\":\"RequestsAuthorizationLevel\",\"Value\":0},{\"Key\":\"AccessWithoutConfirmation\",\"Value\":true},{\"Key\":\"CreateFolders\", \"Value\":true},{\"Key\":\"DeleteFolders\", \"Value\":true},{\"Key\":\"MoveAccountsAndFolders\",\"Value\":true}]}}");
            membersToAdd.Add("EVDGroup", "{\"member\":{\"MemberName\": \"EVDGroup\" , \"SearchIn\":\"Vault\",\"MembershipExpirationDate\":\"\",\"Permissions\":[{\"Key\":\"UseAccounts\", \"Value\":false},{\"Key\":\"RetrieveAccounts\", \"Value\":false},{\"Key\":\"ListAccounts\", \"Value\":true},{\"Key\":\"AddAccounts\", \"Value\":false},{\"Key\":\"UpdateAccountContent\",\"Value\":false},{\"Key\":\"UpdateAccountProperties\",\"Value\":false},{\"Key\":\"InitiateCPMAccountManagementOperations\",\"Value\":false},{\"Key\":\"SpecifyNextAccountContent\",\"Value\":false},{\"Key\":\"RenameAccounts\", \"Value\":false},{\"Key\":\"DeleteAccounts\", \"Value\":false},{\"Key\":\"UnlockAccounts\", \"Value\":false},{\"Key\":\"ManageSafe\", \"Value\":false},{\"Key\":\"ManageSafeMembers\", \"Value\":false},{\"Key\":\"BackupSafe\", \"Value\":false},{\"Key\":\"ViewAuditLog\", \"Value\":true},{\"Key\":\"ViewSafeMembers\", \"Value\":true},{\"Key\":\"RequestsAuthorizationLevel\",\"Value\":0},{\"Key\":\"AccessWithoutConfirmation\",\"Value\":false},{\"Key\":\"CreateFolders\", \"Value\":false},{\"Key\":\"DeleteFolders\", \"Value\":false},{\"Key\":\"MoveAccountsAndFolders\",\"Value\":false}]}}");

            foreach (string member in membersToAdd.AllKeys) {
                logger.Info("  -> add member " + member);
                serverResponse = CFNUtils.SendHttpRequest(session_token, "POST", update_safe_member_endpoint, membersToAdd[member]);

                if (serverResponse.cyberarkError != null && serverResponse.cyberarkError.ErrorMessage.Contains("is already a member")) {
                    logger.Info(member + " is already member of this safe");
                } else if (CFNUtils.IsFailure(serverResponse)) {
                    AddErrorMessage("Failed to add " + member + " member, check logs for more details");
                    //return;
                }
            }

            // **************** Add AD Group members *********************
            string managerGroup = isMars ? "L_" + cleanSafeName.Replace(' ', '-') + "_Gst" : "G_" + cleanSafeName.Replace(' ', '-') + "_Gst";
            string userGroup = isMars ? "L_" + cleanSafeName.Replace(' ', '-') + "_Usr" : "G_" + cleanSafeName.Replace(' ', '-') + "_Usr";
            string searchIn = isMars ? "ADGRAAL" : "ADCIB";

            string ADserver = isMars ? ConfigurationManager.AppSettings["ADserverGraal"] : ConfigurationManager.AppSettings["ADserver"];
            string ADdomain = isMars ? ConfigurationManager.AppSettings["ADdomainGraal"] : ConfigurationManager.AppSettings["ADdomain"];
            string ADaccount = isMars ? ConfigurationManager.AppSettings["ADAccountGraal"] : ConfigurationManager.AppSettings["ADAccount"];
            string ADaccountObjectName = isMars ? ConfigurationManager.AppSettings["ADAccountGraalObjectName"] : ConfigurationManager.AppSettings["ADAccountObjectName"];
            string ADaccountSafeName = isMars ? ConfigurationManager.AppSettings["ADAccountGraalSafeName"] : ConfigurationManager.AppSettings["ADAccountSafeName"];
            string ADpassword = null;
            string graalScope = "OU=_GROUPS,DC=graal,DC=net";
            string cibScope = "OU=Groups,OU=_EMEA-FR,DC=cib,DC=net";
            string scope = isMars ? graalScope : cibScope;

            ADaccountSafeName = String.IsNullOrEmpty(ADaccountSafeName) ? "CF-AIM-W61" : ADaccountSafeName;

            try
            {
                logger.Debug("--> Request AD browsing account password ..");
                ADpassword = CFNUtils.AIMGetPassword(ADaccountSafeName, CFNUtils.app_id, ADaccountObjectName);
                logger.Debug("--> AD browsing account password fetched");
            }
            catch (PSDKException ex)
            {
                AddErrorMessage("ERROR: Failed to get password AD browsing account  : " + ex.Reason);
                logger.Error("ERROR: Failed to get password AD browsing account: " + ex.Reason);
                return;
            }

            //string managerGroupDn = FindAdGroup(managerGroup, isMars);
            //string userGroupDn = FindAdGroup(userGroup, isMars);

            string managerGroupDn = null;
            string userGroupDn = null;
            LdapConnection ldapConn = CFNUtils.LdapConnectAD(ADserver, ADdomain, ADaccount, ADpassword);
            if (ldapConn != null)
            {
                managerGroupDn = CFNUtils.FindAdGroupLdap(ldapConn, managerGroup, "DistinguishedName",scope);
                userGroupDn = CFNUtils.FindAdGroupLdap(ldapConn, managerGroup, "DistinguishedName", scope);
            }
            if (ldapConn != null)
            {
                ldapConn.Dispose();
            }
            if (!String.IsNullOrEmpty(managerGroupDn))
            {
                logger.Info("  -> add member " + managerGroup);
                serverResponse = CFNUtils.SendHttpRequest(session_token, "POST", update_safe_member_endpoint, "{\"member\":{\"MemberName\":\"" + managerGroup + "\" , \"SearchIn\":\"" + searchIn + "\",\"MembershipExpirationDate\":\"\",\"Permissions\":[{\"Key\":\"UseAccounts\", \"Value\":true},{\"Key\":\"RetrieveAccounts\", \"Value\":true},{\"Key\":\"ListAccounts\", \"Value\":true},{\"Key\":\"AddAccounts\", \"Value\":true},{\"Key\":\"UpdateAccountContent\",\"Value\":true},{\"Key\":\"UpdateAccountProperties\",\"Value\":true},{\"Key\":\"InitiateCPMAccountManagementOperations\",\"Value\":true},{\"Key\":\"SpecifyNextAccountContent\",\"Value\":true},{\"Key\":\"RenameAccounts\", \"Value\":true},{\"Key\":\"DeleteAccounts\", \"Value\":true},{\"Key\":\"UnlockAccounts\", \"Value\":false},{\"Key\":\"ManageSafe\", \"Value\":false},{\"Key\":\"ManageSafeMembers\", \"Value\":false},{\"Key\":\"BackupSafe\", \"Value\":false},{\"Key\":\"ViewAuditLog\", \"Value\":true},{\"Key\":\"ViewSafeMembers\", \"Value\":true},{\"Key\":\"RequestsAuthorizationLevel\",\"Value\":0},{\"Key\":\"AccessWithoutConfirmation\",\"Value\":false},{\"Key\":\"CreateFolders\", \"Value\":true},{\"Key\":\"DeleteFolders\", \"Value\":true},{\"Key\":\"MoveAccountsAndFolders\",\"Value\":true}]}}");
                if (serverResponse.cyberarkError != null && serverResponse.cyberarkError.ErrorMessage.Contains("is already a member"))
                {
                    logger.Info(managerGroup+ " is already member of this safe");
                }
                else if (CFNUtils.IsFailure(serverResponse))
                {
                        createGroupsWithPacli = true;
                }
               
            }
            if (!String.IsNullOrEmpty(userGroupDn))
            {
                logger.Info("  -> add member " + userGroup);
                serverResponse = CFNUtils.SendHttpRequest(session_token, "POST", update_safe_member_endpoint, "{\"member\":{\"MemberName\":\"" + userGroup + "\" , \"SearchIn\":\"" + searchIn + "\",\"MembershipExpirationDate\":\"\",\"Permissions\":[{\"Key\":\"UseAccounts\", \"Value\":true},{\"Key\":\"RetrieveAccounts\", \"Value\":true},{\"Key\":\"ListAccounts\", \"Value\":true},{\"Key\":\"AddAccounts\", \"Value\":false},{\"Key\":\"UpdateAccountContent\",\"Value\":false},{\"Key\":\"UpdateAccountProperties\",\"Value\":false},{\"Key\":\"InitiateCPMAccountManagementOperations\",\"Value\":false},{\"Key\":\"SpecifyNextAccountContent\",\"Value\":false},{\"Key\":\"RenameAccounts\", \"Value\":false},{\"Key\":\"DeleteAccounts\", \"Value\":false},{\"Key\":\"UnlockAccounts\", \"Value\":false},{\"Key\":\"ManageSafe\", \"Value\":false},{\"Key\":\"ManageSafeMembers\", \"Value\":false},{\"Key\":\"BackupSafe\", \"Value\":false},{\"Key\":\"ViewAuditLog\", \"Value\":false},{\"Key\":\"ViewSafeMembers\", \"Value\":false},{\"Key\":\"RequestsAuthorizationLevel\",\"Value\":0},{\"Key\":\"AccessWithoutConfirmation\",\"Value\":false},{\"Key\":\"CreateFolders\", \"Value\":false},{\"Key\":\"DeleteFolders\", \"Value\":false},{\"Key\":\"MoveAccountsAndFolders\",\"Value\":false}]}}");
                if (serverResponse.cyberarkError != null && serverResponse.cyberarkError.ErrorMessage.Contains("is already a member"))
                {
                    logger.Info(userGroup + " is already member of this safe");
                }
                else if (CFNUtils.IsFailure(serverResponse))
                {
                    createGroupsWithPacli = true;
                }
               

            }

            // **************** Remove CreateUser *********************
            if (removeCreateUser)
            {
                logger.Info("-> Remove " + CFNUtils.vault_user);
                string remove_createUser_endpoint = "/PasswordVault/WebServices/PIMServices.svc/Safes/" + cleanSafeName + "/Members/" + CFNUtils.vault_user;
                serverResponse = CFNUtils.SendHttpRequest(session_token, "DELETE", remove_createUser_endpoint, "");
                if (CFNUtils.IsFailure(serverResponse))
                {
                    AddErrorMessage("Failed to remove " + CFNUtils.vault_user + " from safe " + cleanSafeName);
                }
            }

            // ************************ Logout ***************************************
            logger.Info("--> Logout from CFN");
            CFNUtils.LogoffVault(session_token);
           

            // ************************ Update security level and onboard AD groups if needed ***************************************
            logger.Info("--> Update safe security level");
            string templateFile = "updateSecurityLevelTemplate.txt"; 
            NameValueCollection replacementDict = new NameValueCollection();
            replacementDict.Add("%SAFENAME%", cleanSafeName);
            replacementDict.Add("%VAULTUSER%", CFNUtils.vault_user);
            if (createGroupsWithPacli)
            {
                templateFile = "updateSecurityLevelAndAddGroupsTemplate.txt";
                replacementDict.Add("%GSTGROUPDN%", managerGroupDn);
                replacementDict.Add("%GSTGROUP%", managerGroup);
                replacementDict.Add("%USRGROUPDN%", userGroupDn);
                replacementDict.Add("%USRGROUP%", userGroup);
                int rc = CFNUtils.RunPacliCmds(Server.MapPath(@"~/App_Data"), templateFile, replacementDict);
                if (rc != 0)
                {
                    AddErrorMessage("PACLI execution returned error code");
                }
            }
            infosLabel.Text = "The Safe was created successfully";
            logger.Info("Done.");
        }

        private string FindAdGroup(string adGroup, bool isMars)
        {
          
            // Querying Active Directory
            System.Security.Principal.WindowsImpersonationContext impersonationContext;
            impersonationContext = ((System.Security.Principal.WindowsIdentity)User.Identity).Impersonate();

            //Récupération des variables depuis le fichier de configuration
            string ADserver = isMars ? ConfigurationManager.AppSettings["ADserverGraal"] : ConfigurationManager.AppSettings["ADserver"];
            string ADdomain = isMars ? ConfigurationManager.AppSettings["ADdomainGraal"] : ConfigurationManager.AppSettings["ADdomain"];
            string ADaccount = isMars ? ConfigurationManager.AppSettings["ADAccountGraal"] : ConfigurationManager.AppSettings["ADAccount"];
            string ADaccountObjectName = isMars ? ConfigurationManager.AppSettings["ADAccountGraalObjectName"] : ConfigurationManager.AppSettings["ADAccountObjectName"];
            string ADaccountSafeName = isMars ? ConfigurationManager.AppSettings["ADAccountGraalSafeName"] : ConfigurationManager.AppSettings["ADAccountSafeName"];
            string ADpassword = null;
            string adGroupDn = null;
       

            ADaccountSafeName = String.IsNullOrEmpty(ADaccountSafeName) ? "CF-AIM-W61" : ADaccountSafeName;

            try
            {
                logger.Debug("--> Request AD browsing account password ..");
                ADpassword = CFNUtils.AIMGetPassword(ADaccountSafeName, CFNUtils.app_id, ADaccountObjectName);
                logger.Debug("--> AD browsing account password fetched");
            }
            catch (PSDKException ex)
            {
                AddErrorMessage("ERROR: Failed to get password AD browsing account  : " + ex.Reason);
                logger.Error("ERROR: Failed to get password AD browsing account: " + ex.Reason);
                return null;
            }

            PrincipalContext ctx = null;
            try
            {
                if (CFNUtils.useSSL)
                {

                    ADserver = ADserver + ":636";
                    ContextOptions options = ContextOptions.SimpleBind | ContextOptions.SecureSocketLayer;
                    ctx = new PrincipalContext(ContextType.Domain, ADserver, ADdomain, options, ADaccount, ADpassword);

                }
                else
                {
                    ctx = new PrincipalContext(ContextType.Domain, ADserver, ADdomain, ADaccount, ADpassword);
                }
                PrincipalSearcher srch = new PrincipalSearcher(new GroupPrincipal(ctx, adGroup));
                logger.Debug("--> Searching group " + adGroup);
                Principal principal = srch.FindOne();

                if (principal == null)
                {
                    logger.Error("Unable to find group "+ adGroup);
                    AddErrorMessage("Unable to find group " + adGroup);
                }
                else
                {
                    adGroupDn = principal.DistinguishedName;
                }
            }
            catch (Exception e)
            {
                logger.Error("Failed to search group "+ adGroup + " in AD :" + e.Message);
                AddErrorMessage("Failed to search group "+ adGroup +" in AD :" + e.Message);
            }
            finally
            {
                impersonationContext.Undo();
            }
            return adGroupDn;
        }



        private void AddErrorMessage(String message)
        {
            ((SiteMaster)(this.Master)).publishError(message);
        } 
     
