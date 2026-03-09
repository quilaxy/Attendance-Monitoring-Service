using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace EventLogOutEmployeeService
{
    public class SharePointIntegration
    {
        private readonly string _tenantId;
        private readonly string _clientId;
        private readonly string _clientSecret;
        private readonly string _siteId;
        private readonly string _listId;
        private readonly string? _summaryListId;
        private static bool _hasWaitedForNetwork = false;
        private static readonly object _networkWaitLock = new object();
        private static DateTime _lastShutdownEventTime = DateTime.MinValue;
        private static DateTime _lastSleepEventTime = DateTime.MinValue;
        private static readonly TimeSpan ShutdownEventWindow = TimeSpan.FromMinutes(2);
        private static readonly TimeSpan SleepEventWindow = TimeSpan.FromHours(2);

        public static void SetServiceStartTime(DateTime startTime)
        {
            _ = startTime;
        }

        public static void MarkShutdownEvent(DateTime eventTime)
        {
            _lastShutdownEventTime = eventTime;
        }

        public static void MarkSleepEvent(DateTime eventTime)
        {
            _lastSleepEventTime = eventTime;
        }

        public static bool IsValidWakeEvent(DateTime eventTime)
        {
            var timeSinceSleep = eventTime - _lastSleepEventTime;
            return (timeSinceSleep.TotalHours > 0 && timeSinceSleep.TotalHours <= 2);
        }

        public SharePointIntegration()
        {
            try
            {
                string basePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "");
                var configuration = LoadConfiguration(basePath);

                var azureSettings = configuration.GetSection("AzureSettings");
                var sharePointSettings = configuration.GetSection("SharePointSettings");

                _tenantId = azureSettings["TenantId"] ?? throw new InvalidOperationException("AzureSettings:TenantId is missing");
                _clientId = azureSettings["ClientId"] ?? throw new InvalidOperationException("AzureSettings:ClientId is missing");
                _clientSecret = azureSettings["ClientSecret"] ?? throw new InvalidOperationException("AzureSettings:ClientSecret is missing");
                _siteId = sharePointSettings["SiteId"] ?? throw new InvalidOperationException("SharePointSettings:SiteId is missing");
                _listId = sharePointSettings["ListId"] ?? throw new InvalidOperationException("SharePointSettings:ListId is missing");
                _summaryListId = sharePointSettings["SummaryListId"];
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("Application",
                    $"Error loading SharePoint configuration: {ex.Message}",
                    EventLogEntryType.Error, 1012);
                throw;
            }
        }


        private IConfiguration LoadConfiguration(string baseDirectory)
        {
            string plainConfigPath = Path.Combine(baseDirectory, "appsettings.json");
            if (File.Exists(plainConfigPath))
            {
                var plainConfigBuilder = new ConfigurationBuilder()
                    .SetBasePath(baseDirectory)
                    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: false);

                return plainConfigBuilder.Build();
            }

            string encryptedConfigPath = Path.Combine(baseDirectory, "appsettings.json.encrypted");
            if (!File.Exists(encryptedConfigPath))
            {
                throw new FileNotFoundException(
                    $"Configuration file not found. Expected either '{plainConfigPath}' or '{encryptedConfigPath}'.");
            }

            byte[] encryptedData = File.ReadAllBytes(encryptedConfigPath);
            byte[] decryptedData = ProtectedData.Unprotect(
                encryptedData,
                null,
                DataProtectionScope.LocalMachine
            );

            string jsonContent = Encoding.UTF8.GetString(decryptedData);

            var configBuilder = new ConfigurationBuilder();
            using (var stream = new MemoryStream(Encoding.UTF8.GetBytes(jsonContent)))
            {
                configBuilder.AddJsonStream(stream);
            }

            return configBuilder.Build();
        }

        public async Task<string?> GetAccessTokenAsync(DateTime eventTime, int eventId)
        {
            bool isShutdownEvent = (eventId == 1074 || eventId == 6006 || eventId == 4647 || eventId == 6008 || eventId == 41 || eventId == 42);
            bool inShutdownWindow = (DateTime.Now - _lastShutdownEventTime) < ShutdownEventWindow;
            bool needsNetworkWait = false;

            if (!_hasWaitedForNetwork)
            {
                if (isShutdownEvent || inShutdownWindow)
                {
                    _hasWaitedForNetwork = true;
                }
                else
                {
                    needsNetworkWait = true;
                }
            }

            lock (_networkWaitLock)
            {
                if (needsNetworkWait && !_hasWaitedForNetwork)
                {
                    Thread.Sleep(30000);
                    _hasWaitedForNetwork = true;
                }
            }

            string authority = $"https://login.microsoftonline.com/{_tenantId}/oauth2/v2.0/token";
            int maxRetries = 3;
            int delayMs = 5000;

            for (int attempt = 1; attempt <= maxRetries; attempt++)
            {
                try
                {
                    using (var client = new HttpClient())
                    {
                        client.Timeout = TimeSpan.FromSeconds(30);

                        var requestBody = new StringContent(
                            $"grant_type=client_credentials&client_id={_clientId}&client_secret={_clientSecret}&scope=https://graph.microsoft.com/.default",
                            Encoding.UTF8,
                            "application/x-www-form-urlencoded"
                        );

                        HttpResponseMessage response = await client.PostAsync(authority, requestBody);
                        if (response.IsSuccessStatusCode)
                        {
                            string responseBody = await response.Content.ReadAsStringAsync();
                            var token = JsonConvert.DeserializeObject<TokenResponse>(responseBody);
                            return token?.access_token;
                        }
                        else
                        {
                            if (attempt < maxRetries)
                            {
                                await Task.Delay(delayMs);
                                delayMs *= 2;
                            }
                            else
                            {
                                throw new Exception($"Failed to get access token after {maxRetries} attempts");
                            }
                        }
                    }
                }
                catch (HttpRequestException ex) when (ex.InnerException is SocketException)
                {
                    if (attempt < maxRetries)
                    {
                        await Task.Delay(delayMs);
                        delayMs *= 2;
                    }
                    else
                    {
                        throw;
                    }
                }
                catch (Exception)
                {
                    if (attempt < maxRetries)
                    {
                        await Task.Delay(delayMs);
                        delayMs *= 2;
                    }
                    else
                    {
                        throw;
                    }
                }
            }

            return null;
        }

        public async Task AddRecordToSharePointAsync(string accessToken, string username, DateTime eventTime, int eventId, string eventType, string computerName)
        {
            bool isShutdownEvent = (eventId == 1074 || eventId == 6006 || eventId == 4647 || eventId == 6008 || eventId == 41 || eventId == 42);

            int maxRetries = isShutdownEvent ? 2 : 3;
            int timeoutSeconds = isShutdownEvent ? 10 : 30;
            int delayMs = isShutdownEvent ? 1000 : 3000;

            for (int attempt = 1; attempt <= maxRetries; attempt++)
            {
                try
                {
                    string eventTimeLocal = eventTime.ToString("yyyy-MM-ddTHH:mm:ss");

                    string title = $"{computerName}\\{eventId}\\{username}";

                    var postData = new
                    {
                        fields = new
                        {
                            Title = title,
                            Username = username,
                            EventID = eventId,
                            EventTime = eventTimeLocal,
                            EventType = eventType,
                            ComputerName = computerName
                        }
                    };

                    using (var client = new HttpClient())
                    {
                        client.Timeout = TimeSpan.FromSeconds(timeoutSeconds);
                        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                        client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                        string escapedTitle = EscapeODataLiteral(title);
                        string escapedEventTime = EscapeODataLiteral(eventTimeLocal);
                        string checkUrl = $"https://graph.microsoft.com/v1.0/sites/{_siteId}/lists/{_listId}/items?$expand=fields&$filter=fields/Title eq '{escapedTitle}' and fields/EventTime eq '{escapedEventTime}'&$top=1";
                        HttpResponseMessage checkResponse = await client.GetAsync(checkUrl);

                        if (checkResponse.IsSuccessStatusCode)
                        {
                            var checkBody = await checkResponse.Content.ReadAsStringAsync();
                            var checkObject = JsonConvert.DeserializeObject<JObject>(checkBody);
                            var existingItems = checkObject?["value"] as JArray;

                            if (existingItems != null && existingItems.Count > 0)
                            {
                                return;
                            }
                        }

                        var content = new StringContent(JsonConvert.SerializeObject(postData), Encoding.UTF8, "application/json");

                        string url = $"https://graph.microsoft.com/v1.0/sites/{_siteId}/lists/{_listId}/items";

                        HttpResponseMessage response = await client.PostAsync(url, content);

                        if (response.IsSuccessStatusCode)
                        {
                            return;
                        }
                        else
                        {
                            if (attempt < maxRetries)
                            {
                                await Task.Delay(delayMs);
                                delayMs = Math.Min(delayMs * 2, 10000);
                            }
                        }
                    }
                }
                catch (Exception)
                {
                    if (attempt < maxRetries)
                    {
                        await Task.Delay(delayMs);
                        delayMs = Math.Min(delayMs * 2, 10000);
                    }
                }
            }
        }

        public async Task UpsertDailySummaryLoginAsync(string accessToken, string username, string computerName, DateTime loginTime)
        {
            if (string.IsNullOrWhiteSpace(_summaryListId))
                return;

            string workDate = loginTime.ToString("yyyy-MM-dd");
            string summaryKey = BuildSummaryKey(computerName, username, workDate);
            DateTime expectedTimeOut = loginTime.AddHours(9);

            using var client = CreateGraphClient(accessToken, 30);
            string escapedSummaryKey = EscapeODataLiteral(summaryKey);
            string findUrl = $"https://graph.microsoft.com/v1.0/sites/{_siteId}/lists/{_summaryListId}/items?$expand=fields&$filter=fields/Title eq '{escapedSummaryKey}'&$top=1";

            HttpResponseMessage findResponse = await client.GetAsync(findUrl);
            if (!findResponse.IsSuccessStatusCode)
                return;

            var findBody = await findResponse.Content.ReadAsStringAsync();
            var findObject = JsonConvert.DeserializeObject<JObject>(findBody);
            var existingItems = findObject?["value"] as JArray;

            if (existingItems != null && existingItems.Count > 0)
            {
                return;
            }

            var postData = new
            {
                fields = new
                {
                    Title = summaryKey,
                    Username = username,
                    ComputerName = computerName,
                    WorkDate = workDate,
                    LoginTime = loginTime.ToString("yyyy-MM-ddTHH:mm:ss"),
                    ExpectedTimeOut = expectedTimeOut.ToString("yyyy-MM-ddTHH:mm:ss"),
                    ShutdownType = string.Empty
                }
            };

            var createContent = new StringContent(JsonConvert.SerializeObject(postData), Encoding.UTF8, "application/json");
            await client.PostAsync($"https://graph.microsoft.com/v1.0/sites/{_siteId}/lists/{_summaryListId}/items", createContent);
        }

        public async Task TryUpdateDailySummaryShutdownAsync(string accessToken, string username, string computerName, DateTime shutdownTime, int eventId, string eventType)
        {
            if (string.IsNullOrWhiteSpace(_summaryListId))
                return;

            string workDate = shutdownTime.ToString("yyyy-MM-dd");
            string summaryKey = BuildSummaryKey(computerName, username, workDate);

            using var client = CreateGraphClient(accessToken, 30);
            string escapedSummaryKey = EscapeODataLiteral(summaryKey);
            string findUrl = $"https://graph.microsoft.com/v1.0/sites/{_siteId}/lists/{_summaryListId}/items?$expand=fields&$filter=fields/Title eq '{escapedSummaryKey}'&$top=1";

            HttpResponseMessage findResponse = await client.GetAsync(findUrl);
            if (!findResponse.IsSuccessStatusCode)
                return;

            var findBody = await findResponse.Content.ReadAsStringAsync();
            var findObject = JsonConvert.DeserializeObject<JObject>(findBody);
            var existingItems = findObject?["value"] as JArray;
            if (existingItems == null || existingItems.Count == 0)
                return;

            var summaryItem = existingItems[0];
            string? itemId = summaryItem?["id"]?.ToString();
            if (string.IsNullOrWhiteSpace(itemId))
                return;

            var fields = summaryItem?["fields"] as JObject;
            DateTime? loginTime = ParseFieldDateTime(fields, "LoginTime");
            DateTime? expectedTimeOut = ParseFieldDateTime(fields, "ExpectedTimeOut");
            DateTime? currentShutdown = ParseFieldDateTime(fields, "ShutdownTime");
            string? currentShutdownType = fields?["ShutdownType"]?.ToString();

            if (!IsValidShutdownCandidate(eventId, eventType, shutdownTime, loginTime, expectedTimeOut))
                return;

            int newPriority = GetShutdownPriority(eventId, eventType);
            int currentPriority = GetPriorityFromShutdownType(currentShutdownType);

            if (newPriority < currentPriority)
                return;

            if (newPriority == currentPriority && currentShutdown.HasValue && currentShutdown.Value >= shutdownTime)
                return;

            string shutdownType = BuildShutdownType(eventId, eventType);
            var updateData = new
            {
                fields = new
                {
                    ShutdownTime = shutdownTime.ToString("yyyy-MM-ddTHH:mm:ss"),
                    ShutdownType = shutdownType
                }
            };

            var patchContent = new StringContent(JsonConvert.SerializeObject(updateData), Encoding.UTF8, "application/json");
            using var patchRequest = new HttpRequestMessage(new HttpMethod("PATCH"), $"https://graph.microsoft.com/v1.0/sites/{_siteId}/lists/{_summaryListId}/items/{itemId}/fields")
            {
                Content = patchContent
            };

            await client.SendAsync(patchRequest);
        }

        private HttpClient CreateGraphClient(string accessToken, int timeoutSeconds)
        {
            var client = new HttpClient
            {
                Timeout = TimeSpan.FromSeconds(timeoutSeconds)
            };

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            return client;
        }

        private static string BuildSummaryKey(string computerName, string username, string workDate)
        {
            return $"{computerName}\\{username}\\{workDate}";
        }

        private static string EscapeODataLiteral(string value)
        {
            return value.Replace("'", "''");
        }

        private static DateTime? ParseFieldDateTime(JObject? fields, string fieldName)
        {
            string? value = fields?[fieldName]?.ToString();
            if (string.IsNullOrWhiteSpace(value))
                return null;

            return DateTime.TryParse(value, out DateTime parsed) ? parsed : null;
        }

        private static string BuildShutdownType(int eventId, string eventType)
        {
            return $"{eventId} - {eventType}";
        }

        private static int GetPriorityFromShutdownType(string? shutdownType)
        {
            if (string.IsNullOrWhiteSpace(shutdownType))
                return 0;

            string[] parts = shutdownType.Split('-', 2, StringSplitOptions.TrimEntries);
            if (parts.Length == 0)
                return 0;

            if (!int.TryParse(parts[0], out int existingEventId))
                return 0;

            string existingEventType = parts.Length > 1 ? parts[1] : string.Empty;
            return GetShutdownPriority(existingEventId, existingEventType);
        }

        private static bool IsValidShutdownCandidate(int eventId, string eventType, DateTime shutdownTime, DateTime? loginTime, DateTime? expectedTimeOut)
        {
            if (eventId == 1074 && eventType.Contains("Restart", StringComparison.OrdinalIgnoreCase))
                return false;

            DateTime referenceLogin = loginTime ?? shutdownTime.AddHours(-9);
            DateTime referenceExpected = expectedTimeOut ?? referenceLogin.AddHours(9);

            if (eventId == 6008 || eventId == 41)
            {
                return shutdownTime >= referenceExpected;
            }

            if (eventId == 4647)
            {
                return shutdownTime >= referenceExpected.AddHours(-2);
            }

            return true;
        }

        private static int GetShutdownPriority(int eventId, string eventType)
        {
            if (eventId == 6006)
                return 5;

            if (eventId == 1074 && !eventType.Contains("Restart", StringComparison.OrdinalIgnoreCase))
                return 4;

            if (eventId == 4647)
                return 3;

            if (eventId == 6008)
                return 2;

            if (eventId == 41)
                return 1;

            return 0;
        }

        public async Task CleanupOldRecordsAsync(int retentionMonths = 6)
        {
            try
            {
                string? accessToken = await GetAccessTokenAsync(DateTime.Now, 0);

                if (string.IsNullOrEmpty(accessToken))
                    return;

                DateTime cutoffDate = DateTime.Now.AddMonths(-retentionMonths);

                using (var client = new HttpClient())
                {
                    client.Timeout = TimeSpan.FromMinutes(5);
                    client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                    client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                    client.DefaultRequestHeaders.Add("Prefer", "HonorNonIndexedQueriesWarningMayFailRandomly");

                    string url = $"https://graph.microsoft.com/v1.0/sites/{_siteId}/lists/{_listId}/items?$expand=fields&$select=id,fields&$top=5000";

                    HttpResponseMessage response = await client.GetAsync(url);
                    string responseContent = await response.Content.ReadAsStringAsync();

                    if (!response.IsSuccessStatusCode)
                        return;

                    var result = JsonConvert.DeserializeObject<JObject>(responseContent);
                    var items = result?["value"] as JArray;

                    if (items == null || items.Count == 0)
                        return;

                    foreach (JToken item in items)
                    {
                        try
                        {
                            var fields = item["fields"] as JObject;
                            string? eventTimeStr = fields?["EventTime"]?.ToString();
                            if (string.IsNullOrWhiteSpace(eventTimeStr))
                                continue;

                            if (!DateTime.TryParse(eventTimeStr, out DateTime eventTime))
                                continue;

                            if (eventTime < cutoffDate)
                            {
                                string? itemId = item["id"]?.ToString();
                                if (string.IsNullOrWhiteSpace(itemId))
                                    continue;

                                string deleteUrl = $"https://graph.microsoft.com/v1.0/sites/{_siteId}/lists/{_listId}/items/{itemId}";

                                await client.DeleteAsync(deleteUrl);
                                await Task.Delay(200);
                            }
                        }
                        catch
                        {
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("Application",
                    $"Error in cleanup task: {ex.Message}",
                    EventLogEntryType.Warning, 1013);
            }
        }
    }
}
