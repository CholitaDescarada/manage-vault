<%@ Page Title="Create a safe" Language="C#" MasterPageFile="~/Site.master" AutoEventWireup="true"
    CodeBehind="Create.aspx.cs" Inherits="manageVault.Create" %>

<asp:Content ID="HeaderContent" runat="server" ContentPlaceHolderID="HeadContent"/>
<asp:Content ID="BodyContent" runat="server" ContentPlaceHolderID="MainContent">    
    <p>&nbsp;</p>	    
    <table summary=""><tr>
    <td width="100px">&nbsp;</td>
    <td id="aLaUne" width="600px">
        <div class="titleViolet"><asp:Localize runat="server" ID="titleMessage" meta:resourcekey="titleMessage"/></div>
        <div class="encadrementGris">
        <table><tr>
            <td width="600px">
            <!--<p>&nbsp;</p>	
                <asp:Localize runat="server" ID="VaultTypeLabel" meta:resourcekey="VaultTypeLabel"/> : 
                <asp:RadioButtonList ID="rblVaultType" runat="server" RepeatDirection="Horizontal" >
                </asp:RadioButtonList>-->
            <p>
                <asp:Localize runat="server" ID="safeNameLabel" meta:resourcekey="safeNameLabel"/> : <asp:TextBox ID="safeName" runat="server" class="loginfield"/>
                <asp:RequiredFieldValidator ID="RequiredFieldValidator1" runat="server" 
                    ErrorMessage="RequiredFieldValidator" ControlToValidate="safeName" />
            </p>
            <p>
                <asp:Localize runat="server" ID="descriptionLabel" meta:resourcekey="descriptionLabel"/> : <asp:TextBox ID="safeDescription" runat="server"  class="loginfield"/>
                <asp:RequiredFieldValidator ID="RequiredFieldValidator2" runat="server" ErrorMessage="RequiredFieldValidator" ControlToValidate="safeDescription" />
            </p>
            <p>
                <asp:Button ID="btnCreate" runat="server" meta:resourcekey="btnCreate" onclick="btnCreate_Click" />
            </p>
        </td></tr></table></div>
    </td></tr></table>

    <p>
        <asp:Label ID="infosLabel" runat="server" />
    </p>

</asp:Content>
