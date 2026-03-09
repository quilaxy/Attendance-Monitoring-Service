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

        // ── Static shared state ───────────────────────────────────────────────────
        private static bool _hasWaitedForNetwork = false;
        private static readonly object _networkWaitLock = new object();
        private static DateTime _lastShutdownEventTime = DateTime.MinValue;
        private static DateTime _lastSleepEventTime = DateTime.MinValue;
        private static readonly TimeSpan ShutdownEventWindow = TimeSpan.FromMinutes(2);

        // ── Static helpers ────────────────────────────────────────────────────────

        /// <summary>
        /// Must be called on every service start so the network-wait runs fresh.
        /// </summary>
        public static void ResetNetworkWaitFlag()
        {
            lock (_networkWaitLock)
                _hasWaitedForNetwork = false;
        }

        public static void SetServiceStartTime(DateTime startTime) { /* reserved */ }

        public static void MarkShutdownEvent(DateTime eventTime)
            => _lastShutdownEventTime = eventTime;

        public static void MarkSleepEvent(DateTime eventTime)
            => _lastSleepEventTime = eventTime;

        public static bool IsValidWakeEvent(DateTime eventTime)
        {
            var diff = eventTime - _lastSleepEventTime;
            return diff.TotalHours > 0 && diff.TotalHours <= 2;
        }

        // ── Constructor ───────────────────────────────────────────────────────────

        public SharePointIntegration()
        {
            try
            {
                string basePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "");
                var configuration = LoadConfiguration(basePath);

                var azureSettings = configuration.GetSection("AzureSettings");
                var sharePointSettings = configuration.GetSection("SharePointSettings");

                _tenantId     = azureSettings["TenantId"]     ?? throw new InvalidOperationException("AzureSettings:TenantId is missing");
                _clientId     = azureSettings["ClientId"]     ?? throw new InvalidOperationException("AzureSettings:ClientId is missing");
                _clientSecret = azureSettings["ClientSecret"] ?? throw new InvalidOperationException("AzureSettings:ClientSecret is missing");
                _siteId       = sharePointSettings["SiteId"]  ?? throw new InvalidOperationException("SharePointSettings:SiteId is missing");
                _listId       = sharePointSettings["ListId"]  ?? throw new InvalidOperationException("SharePointSettings:ListId is missing");
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

        // ── Configuration ─────────────────────────────────────────────────────────

        private IConfiguration LoadConfiguration(string baseDirectory)
        {
            string plainConfigPath = Path.Combine(baseDirectory, "appsettings.json");
            if (File.Exists(plainConfigPath))
            {
                return new ConfigurationBuilder()
                    .SetBasePath(baseDirectory)
                    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: false)
                    .Build();
            }

            string encryptedConfigPath = Path.Combine(baseDirectory, "appsettings.json.encrypted");
            if (!File.Exists(encryptedConfigPath))
                throw new FileNotFoundException(
                    $"Configuration file not found. Expected '{plainConfigPath}' or '{encryptedConfigPath}'.");

            byte[] encryptedData = File.ReadAllBytes(encryptedConfigPath);
            byte[] decryptedData = ProtectedData.Unprotect(encryptedData, null, DataProtectionScope.LocalMachine);
            string jsonContent = Encoding.UTF8.GetString(decryptedData);

            var configBuilder = new ConfigurationBuilder();
            using var stream = new MemoryStream(Encoding.UTF8.GetBytes(jsonContent));
            configBuilder.AddJsonStream(stream);
            return configBuilder.Build();
        }

        // ── Access token ──────────────────────────────────────────────────────────

        public async Task<string?> GetAccessTokenAsync(DateTime eventTime, int eventId)
        {
            bool isShutdownEvent = IsShutdownEventId(eventId);
            bool inShutdownWindow = (DateTime.Now - _lastShutdownEventTime) < ShutdownEventWindow;
            bool needsNetworkWait = false;

            if (!_hasWaitedForNetwork)
            {
                if (isShutdownEvent || inShutdownWindow)
                {
                    // Shutdown/logoff events must NOT wait — network is going down
                    lock (_networkWaitLock)
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
                    Thread.Sleep(30000); // wait 30 s for network on fresh boot
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
                    using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
                    var body = new StringContent(
                        $"grant_type=client_credentials&client_id={_clientId}&client_secret={_clientSecret}&scope=https://graph.microsoft.com/.default",
                        Encoding.UTF8, "application/x-www-form-urlencoded");

                    var response = await client.PostAsync(authority, body);
                    if (response.IsSuccessStatusCode)
                    {
                        string responseBody = await response.Content.ReadAsStringAsync();
                        var token = JsonConvert.DeserializeObject<TokenResponse>(responseBody);
                        return token?.access_token;
                    }

                    if (attempt < maxRetries) { await Task.Delay(delayMs); delayMs *= 2; }
                    else throw new Exception($"Failed to get access token after {maxRetries} attempts");
                }
                catch (HttpRequestException ex) when (ex.InnerException is SocketException)
                {
                    if (attempt < maxRetries) { await Task.Delay(delayMs); delayMs *= 2; }
                    else throw;
                }
                catch (Exception)
                {
                    if (attempt < maxRetries) { await Task.Delay(delayMs); delayMs *= 2; }
                    else throw;
                }
            }

            return null;
        }

        // ── Raw list record ───────────────────────────────────────────────────────

        /// <summary>
        /// Adds one record to the raw attendance list (listId).
        /// Before inserting, checks whether an identical record (same Title + EventTime) already
        /// exists to guarantee no duplicates even if the service crashes mid-dispatch.
        /// </summary>
        public async Task AddRecordToSharePointAsync(
            string accessToken, string username, DateTime eventTime,
            int eventId, string eventType, string computerName)
        {
            bool isShutdown = IsShutdownEventId(eventId);
            int maxRetries     = isShutdown ? 2 : 3;
            int timeoutSeconds = isShutdown ? 10 : 30;
            int delayMs        = isShutdown ? 1000 : 3000;

            string eventTimeStr = eventTime.ToString("yyyy-MM-ddTHH:mm:ss");
            string title        = $"{computerName}\\{eventId}\\{username}";

            for (int attempt = 1; attempt <= maxRetries; attempt++)
            {
                try
                {
                    using var client = CreateGraphClient(accessToken, timeoutSeconds);

                    // ── Idempotency check ──────────────────────────────────────
                    string checkUrl = $"https://graph.microsoft.com/v1.0/sites/{_siteId}/lists/{_listId}/items" +
                        $"?$expand=fields&$filter=fields/Title eq '{EscapeODataLiteral(title)}'" +
                        $" and fields/EventTime eq '{EscapeODataLiteral(eventTimeStr)}'&$top=1";

                    var checkResponse = await client.GetAsync(checkUrl);
                    if (checkResponse.IsSuccessStatusCode)
                    {
                        var checkBody = JsonConvert.DeserializeObject<JObject>(
                            await checkResponse.Content.ReadAsStringAsync());
                        if ((checkBody?["value"] as JArray)?.Count > 0)
                            return; // already exists — skip
                    }

                    // ── Insert ────────────────────────────────────────────────
                    var postData = new
                    {
                        fields = new
                        {
                            Title        = title,
                            Username     = username,
                            EventID      = eventId,
                            EventTime    = eventTimeStr,
                            EventType    = eventType,
                            ComputerName = computerName
                        }
                    };

                    var content  = new StringContent(JsonConvert.SerializeObject(postData), Encoding.UTF8, "application/json");
                    var response = await client.PostAsync(
                        $"https://graph.microsoft.com/v1.0/sites/{_siteId}/lists/{_listId}/items", content);

                    if (response.IsSuccessStatusCode) return;

                    if (attempt < maxRetries) { await Task.Delay(delayMs); delayMs = Math.Min(delayMs * 2, 10000); }
                }
                catch (Exception)
                {
                    if (attempt < maxRetries) { await Task.Delay(delayMs); delayMs = Math.Min(delayMs * 2, 10000); }
                }
            }
        }

        // ── Summary list — Login ──────────────────────────────────────────────────

        /// <summary>
        /// Creates (or keeps existing) a daily summary row for the given user+computer+workDate.
        ///
        /// Rules:
        ///   • Only ONE summary row per (ComputerName, Username, WorkDate).
        ///   • If the row already exists, do NOT update LoginTime — we always keep the earliest
        ///     login recorded. The earliest login was set when the row was first created.
        ///   • If the row does not exist, create it now.
        /// </summary>
        public async Task UpsertDailySummaryLoginAsync(
            string accessToken, string username, string computerName, DateTime loginTime)
        {
            if (string.IsNullOrWhiteSpace(_summaryListId)) return;

            string workDate    = loginTime.ToString("yyyy-MM-dd");
            string summaryKey  = BuildSummaryKey(computerName, username, workDate);
            DateTime expectedTimeOut = loginTime.AddHours(9);

            using var client = CreateGraphClient(accessToken, 30);
            var existingItems = await FindSummaryItemAsync(client, summaryKey);

            if (existingItems != null && existingItems.Count > 0)
            {
                // Row already exists — check if stored LoginTime is later than this event.
                // If so, update it to the earlier time (handles replay ordering edge-cases).
                var existing = existingItems[0];
                string? itemId = existing?["id"]?.ToString();
                var fields = existing?["fields"] as JObject;
                DateTime? storedLogin = ParseFieldDateTime(fields, "LoginTime");

                if (storedLogin.HasValue && loginTime < storedLogin.Value && !string.IsNullOrWhiteSpace(itemId))
                {
                    // Replace with earlier login
                    var updateData = new
                    {
                        fields = new
                        {
                            LoginTime       = loginTime.ToString("yyyy-MM-ddTHH:mm:ss"),
                            ExpectedTimeOut = loginTime.AddHours(9).ToString("yyyy-MM-ddTHH:mm:ss")
                        }
                    };
                    var patchContent = new StringContent(JsonConvert.SerializeObject(updateData), Encoding.UTF8, "application/json");
                    using var patchRequest = new HttpRequestMessage(new HttpMethod("PATCH"),
                        $"https://graph.microsoft.com/v1.0/sites/{_siteId}/lists/{_summaryListId}/items/{itemId}/fields")
                    { Content = patchContent };
                    await client.SendAsync(patchRequest);
                }

                return; // row exists — nothing more to do
            }

            // ── Create new summary row ────────────────────────────────────────────
            var postData = new
            {
                fields = new
                {
                    Title           = summaryKey,
                    Username        = username,
                    ComputerName    = computerName,
                    WorkDate        = workDate,
                    LoginTime       = loginTime.ToString("yyyy-MM-ddTHH:mm:ss"),
                    ExpectedTimeOut = expectedTimeOut.ToString("yyyy-MM-ddTHH:mm:ss"),
                    ShutdownType    = string.Empty
                }
            };

            var createContent = new StringContent(JsonConvert.SerializeObject(postData), Encoding.UTF8, "application/json");
            await client.PostAsync(
                $"https://graph.microsoft.com/v1.0/sites/{_siteId}/lists/{_summaryListId}/items",
                createContent);
        }

        // ── Summary list — Shutdown ───────────────────────────────────────────────

        /// <summary>
        /// Updates the ShutdownTime/ShutdownType on an existing summary row.
        ///
        /// Rules (summary = work-hour tracker, only final shutdown matters):
        ///   • Row must already exist (created by UpsertDailySummaryLoginAsync).
        ///     If no row exists yet, the event is too early in the day — skip.
        ///   • Priority (higher wins): 6006 > 1074-Shutdown > 4647 > 6008/41.
        ///     A lower-priority event never overwrites a higher-priority one.
        ///   • For same priority: keep the LATEST timestamp (most recent shutdown).
        ///   • 4647 (User Logout) is accepted only when the logout time is within
        ///     2 hours before or after expectedTimeOut — mid-day logouts are ignored.
        ///   • 1074 Restart is excluded (not a final shutdown).
        /// </summary>
        public async Task TryUpdateDailySummaryShutdownAsync(
            string accessToken, string username, string computerName,
            DateTime shutdownTime, int eventId, string eventType)
        {
            if (string.IsNullOrWhiteSpace(_summaryListId)) return;

            string workDate   = shutdownTime.ToString("yyyy-MM-dd");
            string summaryKey = BuildSummaryKey(computerName, username, workDate);

            using var client = CreateGraphClient(accessToken, 30);
            var existingItems = await FindSummaryItemAsync(client, summaryKey);

            if (existingItems == null || existingItems.Count == 0)
                return; // no login row yet — skip, cannot record shutdown without login context

            var summaryItem = existingItems[0];
            string? itemId  = summaryItem?["id"]?.ToString();
            if (string.IsNullOrWhiteSpace(itemId)) return;

            var fields          = summaryItem?["fields"] as JObject;
            DateTime? loginTime = ParseFieldDateTime(fields, "LoginTime");
            DateTime? expectedTimeOut = ParseFieldDateTime(fields, "ExpectedTimeOut");
            DateTime? currentShutdown = ParseFieldDateTime(fields, "ShutdownTime");
            string? currentShutdownType = fields?["ShutdownType"]?.ToString();

            // ── Priority check ────────────────────────────────────────────────────
            if (!IsValidShutdownCandidate(eventId, eventType, shutdownTime, loginTime, expectedTimeOut))
                return;

            int newPriority     = GetShutdownPriority(eventId, eventType);
            int currentPriority = GetPriorityFromShutdownType(currentShutdownType);

            if (newPriority < currentPriority)
                return; // existing record has higher priority — don't overwrite

            if (newPriority == currentPriority)
            {
                // Same priority: keep the latest shutdown timestamp
                if (currentShutdown.HasValue && currentShutdown.Value >= shutdownTime)
                    return;
            }

            // ── Patch ─────────────────────────────────────────────────────────────
            string shutdownTypeStr = BuildShutdownType(eventId, eventType);
            var updateData = new
            {
                fields = new
                {
                    ShutdownTime = shutdownTime.ToString("yyyy-MM-ddTHH:mm:ss"),
                    ShutdownType = shutdownTypeStr
                }
            };

            var patchContent = new StringContent(JsonConvert.SerializeObject(updateData), Encoding.UTF8, "application/json");
            using var patchRequest = new HttpRequestMessage(new HttpMethod("PATCH"),
                $"https://graph.microsoft.com/v1.0/sites/{_siteId}/lists/{_summaryListId}/items/{itemId}/fields")
            { Content = patchContent };
            await client.SendAsync(patchRequest);
        }

        // ── Cleanup ───────────────────────────────────────────────────────────────

        public async Task CleanupOldRecordsAsync(int retentionMonths = 6)
        {
            try
            {
                string? accessToken = await GetAccessTokenAsync(DateTime.Now, 0);
                if (string.IsNullOrEmpty(accessToken)) return;

                DateTime cutoffDate = DateTime.Now.AddMonths(-retentionMonths);

                using var client = new HttpClient { Timeout = TimeSpan.FromMinutes(5) };
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                client.DefaultRequestHeaders.Add("Prefer", "HonorNonIndexedQueriesWarningMayFailRandomly");

                string url = $"https://graph.microsoft.com/v1.0/sites/{_siteId}/lists/{_listId}/items" +
                             $"?$expand=fields&$select=id,fields&$top=5000";

                var response = await client.GetAsync(url);
                if (!response.IsSuccessStatusCode) return;

                var result = JsonConvert.DeserializeObject<JObject>(await response.Content.ReadAsStringAsync());
                var items  = result?["value"] as JArray;
                if (items == null || items.Count == 0) return;

                foreach (JToken item in items)
                {
                    try
                    {
                        var itemFields    = item["fields"] as JObject;
                        string? eventTimeStr = itemFields?["EventTime"]?.ToString();
                        if (string.IsNullOrWhiteSpace(eventTimeStr)) continue;
                        if (!DateTime.TryParse(eventTimeStr, out DateTime eventTime)) continue;
                        if (eventTime >= cutoffDate) continue;

                        string? itemId = item["id"]?.ToString();
                        if (string.IsNullOrWhiteSpace(itemId)) continue;

                        await client.DeleteAsync(
                            $"https://graph.microsoft.com/v1.0/sites/{_siteId}/lists/{_listId}/items/{itemId}");
                        await Task.Delay(200);
                    }
                    catch { /* continue deleting */ }
                }
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("Application",
                    $"Error in cleanup task: {ex.Message}",
                    EventLogEntryType.Warning, 1013);
            }
        }

        // ── Private helpers ───────────────────────────────────────────────────────

        private HttpClient CreateGraphClient(string accessToken, int timeoutSeconds)
        {
            var client = new HttpClient { Timeout = TimeSpan.FromSeconds(timeoutSeconds) };
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            return client;
        }

        private async Task<JArray?> FindSummaryItemAsync(HttpClient client, string summaryKey)
        {
            string findUrl = $"https://graph.microsoft.com/v1.0/sites/{_siteId}/lists/{_summaryListId}/items" +
                $"?$expand=fields&$filter=fields/Title eq '{EscapeODataLiteral(summaryKey)}'&$top=1";

            var findResponse = await client.GetAsync(findUrl);
            if (!findResponse.IsSuccessStatusCode) return null;

            var findObject = JsonConvert.DeserializeObject<JObject>(
                await findResponse.Content.ReadAsStringAsync());

            return findObject?["value"] as JArray;
        }

        private static string BuildSummaryKey(string computerName, string username, string workDate)
            => $"{computerName}\\{username}\\{workDate}";

        private static string EscapeODataLiteral(string value)
            => value.Replace("'", "''");

        private static DateTime? ParseFieldDateTime(JObject? fields, string fieldName)
        {
            string? value = fields?[fieldName]?.ToString();
            if (string.IsNullOrWhiteSpace(value)) return null;
            return DateTime.TryParse(value, out DateTime parsed) ? parsed : null;
        }

        private static string BuildShutdownType(int eventId, string eventType)
            => $"{eventId} - {eventType}";

        private static bool IsShutdownEventId(int eventId)
            => eventId == 1074 || eventId == 6006 || eventId == 4647 ||
               eventId == 6008 || eventId == 41 || eventId == 42;

        /// <summary>
        /// Determines whether this shutdown event qualifies to be written into the Summary.
        ///
        /// Exclusion rules:
        ///   • 1074 Restart → never written to Summary (not a real end-of-day).
        ///   • 4647 (User Logout) → only accepted if the logout time is within the window
        ///     [expectedTimeOut - 2h, expectedTimeOut + 2h]. This filters out mid-day
        ///     lock/logoffs while still catching early or slightly-late departures.
        ///   • 6008/41 (Unexpected Shutdown/Crash) → only accepted after expectedTimeOut,
        ///     i.e. the machine crashed at or after the expected end of day.
        ///   • 6006 / 1074-Shutdown → always accepted (highest priority, genuine shutdown).
        /// </summary>
        private static bool IsValidShutdownCandidate(
            int eventId, string eventType,
            DateTime shutdownTime,
            DateTime? loginTime, DateTime? expectedTimeOut)
        {
            // 1074 Restart is never a final shutdown
            if (eventId == 1074 && eventType.Contains("Restart", StringComparison.OrdinalIgnoreCase))
                return false;

            DateTime refExpected = expectedTimeOut
                ?? (loginTime?.AddHours(9) ?? shutdownTime.AddHours(-1));

            // Unexpected shutdown/crash: only count if it happened at or after expected time out
            if (eventId == 6008 || eventId == 41)
                return shutdownTime >= refExpected;

            // User logout: accept if within ±2 h of expectedTimeOut (filters mid-day logouts)
            if (eventId == 4647)
                return shutdownTime >= refExpected.AddHours(-2) &&
                       shutdownTime <= refExpected.AddHours(2);

            // 6006 and 1074-Shutdown: always valid
            return true;
        }

        /// <summary>
        /// Priority for Summary ShutdownTime. Higher value wins.
        /// 6006=5, 1074-Shutdown=4, 4647=3, 6008=2, 41=1
        /// </summary>
        private static int GetShutdownPriority(int eventId, string eventType)
        {
            if (eventId == 6006) return 5;
            if (eventId == 1074 && !eventType.Contains("Restart", StringComparison.OrdinalIgnoreCase)) return 4;
            if (eventId == 4647) return 3;
            if (eventId == 6008) return 2;
            if (eventId == 41)   return 1;
            return 0;
        }

        private static int GetPriorityFromShutdownType(string? shutdownType)
        {
            if (string.IsNullOrWhiteSpace(shutdownType)) return 0;
            string[] parts = shutdownType.Split('-', 2, StringSplitOptions.TrimEntries);
            if (parts.Length == 0 || !int.TryParse(parts[0], out int existingEventId)) return 0;
            string existingEventType = parts.Length > 1 ? parts[1] : string.Empty;
            return GetShutdownPriority(existingEventId, existingEventType);
        }
    }

}
