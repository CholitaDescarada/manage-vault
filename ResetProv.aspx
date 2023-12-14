<%@ Page Title="Reset an AIM provider" Language="C#" MasterPageFile="~/Site.Master" AutoEventWireup="true" CodeBehind="ResetProv.aspx.cs" Inherits="manageVault.ResetProv" %>
<asp:Content ID="Content1" ContentPlaceHolderID="HeadContent" runat="server">
</asp:Content>
<asp:Content ID="BodyContent" runat="server" ContentPlaceHolderID="MainContent">
    <p>&nbsp;</p>	    
    <table summary=""><tr>
    <td width="200px">&nbsp;</td>
    <td id="aLaUne" width="600px">
        <div class="titleViolet"><asp:Localize runat="server" ID="titleMessage" meta:resourcekey="titleMessage"/></div>
        <div class="encadrementGris">
        <table><tr>
            <td width="600px">

            <p>
                <asp:Localize runat="server" ID="ProvidersLabel" meta:resourcekey="ProvidersLabel"/> : <asp:TextBox ID="ProvidersText" runat="server" class="loginfield"/>
                <asp:RequiredFieldValidator ID="RequiredFieldValidator1" runat="server" 
                    ErrorMessage="RequiredFieldValidator" ControlToValidate="ProvidersText" />
            </p>
            <p>
                <asp:Button ID="btnReset" runat="server" meta:resourcekey="btnReset" onclick="btnReset_Click" />
            </p>
        </td></tr></table></div>
    </td></tr></table>

    <p>
        <asp:Label ID="infosLabel" runat="server" />
    </p>
</asp:Content>
