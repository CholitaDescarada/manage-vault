<asp:Content ID="HeaderContent" runat="server" ContentPlaceHolderID="HeadContent"></asp:Content>
<asp:Content ID="BodyContent" runat="server" ContentPlaceHolderID="MainContent">  
    <p>&nbsp;</p>	    
    <table summary=""><tr>
        <td width="100px">&nbsp;</td>
        <td id="aLaUne" width="600px">
            <div class="titleViolet"><asp:Localize runat="server" ID="titleMessage" meta:resourcekey="titleMessage"/></div>
            <div class="encadrementGris">
                <table><tr><td width="600px">
                    <%--Saisie du code IUA obligatoire et normalisée--%>
                    <p>
                        <asp:Localize runat="server" ID="codeIUALabel" meta:resourcekey="codeIUALabel"/>: <asp:TextBox ID="codeIUA" runat="server" class="loginfield"/>
				        <asp:CustomValidator runat="server" ID="codeIUACustomValidator" controltovalidate="codeIUA" onservervalidate="codeIUA_ServerValidate" ErrorMessage="The IUA code must be exactly 3 characters long and use only letters and digits."/>
			            <asp:RequiredFieldValidator ID="RequiredFieldValidator1" runat="server" ErrorMessage="Mandatory field" ControlToValidate="codeIUA"/>
                    </p>
                    <%--Saisie d'une description non obligatoire mais normalisée--%>
                    <p>
                        <asp:Localize runat="server" ID="appDescLabel" meta:resourcekey="appDescLabel"/>: <asp:TextBox ID="appDesc" runat="server" class="loginfield"/>
                        <asp:CustomValidator runat="server" ID="appDescValidator" controltovalidate="appDesc" onservervalidate="appDesc_ServerValidate" ErrorMessage="Special characters other than !#$%()*+,-./:;=?@[\ ]^_`{|}~ are not allowed."/>
                    </p>
                    <%--Saisie d'une liste de providers non obligatoire mais normalisée--%>
                    <p>
                        <asp:Localize runat="server" ID="providersLabel" meta:resourcekey="providersLabel"/>: <asp:TextBox ID="providerName" runat="server" class="loginfield"/>
                        <asp:CustomValidator runat="server" ID="providersValidator" controltovalidate="providerName" onservervalidate="providers_ServerValidate" ErrorMessage="It doesn't look like a valid providers list."/>
                    </p>
                    <%--Saisie d'une liste de users non obligatoire mais normalisée--%>
                    <p>
                        <asp:Localize runat="server" ID="osUsersLabel" meta:resourcekey="osUsersLabel"/>: <asp:TextBox ID="osUsers" runat="server" class="loginfield"/>
                        <asp:CustomValidator runat="server" ID="osUsersValidator" controltovalidate="osUsers" onservervalidate="osUsers_ServerValidate" ErrorMessage="It doesn't look like a valid users list."/>
                    </p>
                    <%--Saisie d'une liste de chemins non obligatoire mais normalisée--%>
                    <p>
                        <asp:Localize runat="server" ID="pathsLabel" meta:resourcekey="pathsLabel"/>: <asp:TextBox ID="paths" runat="server" class="loginfield"/>
                        <asp:CustomValidator runat="server" ID="pathsValidator" controltovalidate="paths" onservervalidate="paths_ServerValidate" ErrorMessage="'<' character is forbidden."/>
                    </p>
                    <p><asp:CheckBox runat="server" ID="pathIsFolder" Text="Path is Folder"/> <asp:CheckBox ID="allowInternalScripts" runat="server" Text="Allow Internal Scripts"/></p>
                    <p><asp:Button  runat ="server" ID="btnCreate" meta:resourcekey="btnCreate" onclick="btnCreate_Click"/></p>
                </td></tr></table>
            </div>
        </td>
    </tr></table>
    <p><asp:TextBox ID="infosLabel" runat="server" TextMode="MultiLine" style="overflow:hidden;width: 800px" BorderStyle="None" Rows="3"/></p>
</asp:Content>
