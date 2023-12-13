Skip to sidebar navigation
Skip to content
Linked Applications
Your work
Projects
Repositories
People
Search for code, commits or repositories
Search for code, commits or repositories...
Help
Inbox
Logged in as PANTALACCI Thomas (EXT) (pantalaccith)
BW8 - Source Code Repository
Clone
Create branch
Create pull request
Create fork
Compare
Reports


Source
Commits
Graphs
Branches
All Branches Graph
Pull requests
Forks
NEWBuilds
Repository settings

BW8 - Source Code Repository
CFN - ManageVault v3
Manage Vault v3
Source
Branchmaster
Branch actions
CFN - ManageVault v3/CFNUtils.cs
ruhlmannol_adm
ruhlmannol_adm
 authored 
5f904504a3a
01 Sep 2022
Edit
Blame
Raw file
Source view
Diff to previous
History
20.13 KBContributors
108
                client.Dispose();
109
            }
110
​
111
            logger.Debug(String.Format("Obtained session token: {0}", session_token));
112
            return session_token;
113
        }
114
​
115
        public static int LogoffVault(string session_token) 
116
        {
117
            //int rc = 0;
118
            logger.Info("Logoff vault ...");
119
            ServerResponse serverResponse = SendHttpRequest(session_token, "POST", "/PasswordVault/WebServices/auth/Cyberark/CyberArkAuthenticationService.svc/Logoff", "");
120
            if (IsFailure(serverResponse)) {
121
                //rc = 1;
122
                return 1;
123
            }
124
            else {
125
                return 0;
126
            }
127
​
128
            //return rc;
129
        }
130
​
131
        public static ServerResponse SendHttpRequest(string session_token, string method, string endpoint, string payload)
132
        {
133
            WebClient client = new WebClient();
134
            client.Headers[HttpRequestHeader.ContentType] = "application/json";
135
            client.Headers[HttpRequestHeader.Authorization] = session_token;
136
​
137
            //logger.Info(String.Format("server_address: {0}\tendpoint: {1}", server_address + endpoint));
138
​
139
            //Debug
140
            /*
141
            if (payload.Contains("G_CF-AIM-XXX-APP_HP_XXX_Gst")) {
142
                logger.Debug("On entre dans la fonction de CFNUtils...");
143
            }
144
            */
145
​
146
            Uri uri = new Uri(String.Format("https://{0}{1}", server_address, endpoint));
147
            string response = "";
148
            WebExceptionStatus status_code = WebExceptionStatus.Success;
149
            CyberarkError error = null;
150
            try {
151
                if (method.ToUpper().Equals("GET")) {
152
                    response = client.DownloadString(uri);
153
                }
154
                else {
155
                    response = client.UploadString(uri, method, payload);
156
                }
157
            }
158
            catch (WebException ex) {
159
                response = GetServerErrorMessages(ex);
160
​
161
                //Debug
162
                /*
163
                if (payload.Contains("G_CF-AIM-XXX-APP_HP_XXX_Gst")) {
164
                    logger.Debug(String.Format("Custom debug - response: {0}", response));
165
                }
166
                */
167
​
168
                if (!String.IsNullOrEmpty(response)) {
169
                    try {
170
                        error = JsonConvert.DeserializeObject<CyberarkError>(response);
171
                    }
172
                    catch (JsonSerializationException e) {
173
                        logger.Debug("Failed to parse Cyberark Error response: " + e.Message);
174
                    }
175
                }
176
                status_code = ex.Status;
177
            }
178
            catch (Exception e) {
179
                logger.Error("Unexpected error: " + e.Message);
180
                status_code = WebExceptionStatus.UnknownError;
181
            }
182
            finally {
183
                client.Dispose();
184
            }
185
​
186
            logger.Debug("Response: " + response + System.Environment.NewLine + "StatusCode: " + status_code.ToString());
187
            return new ServerResponse(response, error, status_code);
188
        }
189
​
190
        private static string GetServerErrorMessages(WebException ex)
191
        {
192
            String serverResponse = "";
193
            logger.Error(ex.Message.ToString());
194
            if (ex.Response != null)
195
            {
196
                try
197
                {
198
                    StreamReader reader = new StreamReader(ex.Response.GetResponseStream());
199
                    serverResponse += reader.ReadToEnd();
200
                }
201
                catch (Exception e)
202
                {
203
                    logger.Debug("Failed to read server response stream: " + e.Message);
204
                }
205
            }
206
            return serverResponse;
207
        }
208
​
209
        public static int RunPacli(string workingDir, string content)
210
        {
211
            int rc = 0;
212
            try {
213
                Process p = new Process();
214
                p.StartInfo.RedirectStandardOutput = true;
215
                p.StartInfo.RedirectStandardError = true;
216
                p.StartInfo.UseShellExecute = false;
217
                p.StartInfo.CreateNoWindow = true;
218
                p.StartInfo.WorkingDirectory = workingDir;
219
                p.StartInfo.FileName = workingDir + "\\Pacli.exe";
220
​
221
                string error = "";
222
                foreach (String line in content.Split('\n'))
223
                {
224
                    p.StartInfo.Arguments = line.Trim();
225
                    logger.Debug("Executing PACLI command: " + line);
226
                    p.Start();
227
                    error = p.StandardError.ReadToEnd();
228
                    p.WaitForExit();
229
                    if (p.ExitCode != 0)
230
                    {
231
                        if (!error.Contains("ITATS673E"))
232
                        {
233
                            logger.Error("PACLI error: " + error);
234
                            rc = 1;
235
                        }
236
                    }
237
                }
238
            }
239
            catch (Exception e)
240
            {
241
                logger.Error("Error while executing PACLI commands: " + e.Message);
242
            }
243
            return rc;
244
        }
245
​
246
        public class ServerResponse
247
        {
248
            public string response;
249
            public CyberarkError cyberarkError;
250
            public WebExceptionStatus statusCode;
251
​
252
            public ServerResponse(string response, CyberarkError error, WebExceptionStatus code)
