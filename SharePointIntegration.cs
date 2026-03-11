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
        private static readonly object _configLock = new object();
        private static bool _configLoaded = false;
        private static string _cachedTenantId = string.Empty;
        private static string _cachedClientId = string.Empty;
        private static string _cachedClientSecret = string.Empty;
        private static string _cachedSiteId = string.Empty;
        private static string _cachedListId = string.Empty;
        private static string? _cachedSummaryListId = null;

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
                EnsureConfigurationLoaded();

                _tenantId = _cachedTenantId;
                _clientId = _cachedClientId;
                _clientSecret = _cachedClientSecret;
                _siteId = _cachedSiteId;
                _listId = _cachedListId;
                _summaryListId = _cachedSummaryListId;
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

        private void EnsureConfigurationLoaded()
        {
            if (_configLoaded)
                return;

            lock (_configLock)
            {
                if (_configLoaded)
                    return;

                string basePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "");
                var configuration = LoadConfiguration(basePath);

                var azureSettings = configuration.GetSection("AzureSettings");
                var sharePointSettings = configuration.GetSection("SharePointSettings");

                _cachedTenantId = azureSettings["TenantId"] ?? throw new InvalidOperationException("AzureSettings:TenantId is missing");
                _cachedClientId = azureSettings["ClientId"] ?? throw new InvalidOperationException("AzureSettings:ClientId is missing");
                _cachedClientSecret = azureSettings["ClientSecret"] ?? throw new InvalidOperationException("AzureSettings:ClientSecret is missing");
                _cachedSiteId = sharePointSettings["SiteId"] ?? throw new InvalidOperationException("SharePointSettings:SiteId is missing");
                _cachedListId = sharePointSettings["ListId"] ?? throw new InvalidOperationException("SharePointSettings:ListId is missing");
                _cachedSummaryListId = sharePointSettings["SummaryListId"];
                _configLoaded = true;
            }
        }

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

            lock (_networkWaitLock)
            {
                bool inShutdownWindow = (DateTime.Now - _lastShutdownEventTime) < ShutdownEventWindow;

                if (!_hasWaitedForNetwork)
                {
                    if (isShutdownEvent || inShutdownWindow)
                    {
                        _hasWaitedForNetwork = true;
                    }
                    else
                    {
                        EventLog.WriteEntry("Application",
                            "[TOKEN] Waiting 30s for network on fresh boot...",
                            EventLogEntryType.Information, 4010);
                        Thread.Sleep(30000);
                        _hasWaitedForNetwork = true;
                    }
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

                    string errorBody = await response.Content.ReadAsStringAsync();
                    EventLog.WriteEntry("Application",
                        $"[TOKEN] Attempt {attempt}/{maxRetries} failed: HTTP {(int)response.StatusCode} — {errorBody}",
                        EventLogEntryType.Warning, 4011);

                    if (attempt < maxRetries) { await Task.Delay(delayMs); delayMs *= 2; }
                    else throw new Exception($"Failed to get access token after {maxRetries} attempts. Last status: {(int)response.StatusCode}");
                }
                catch (HttpRequestException ex) when (ex.InnerException is SocketException)
                {
                    EventLog.WriteEntry("Application",
                        $"[TOKEN] Attempt {attempt}/{maxRetries} network error: {ex.Message}",
                        EventLogEntryType.Warning, 4012);
                    if (attempt < maxRetries) { await Task.Delay(delayMs); delayMs *= 2; }
                    else throw;
                }
                catch (Exception ex)
                {
                    EventLog.WriteEntry("Application",
                        $"[TOKEN] Attempt {attempt}/{maxRetries} exception: {ex.GetType().Name}: {ex.Message}",
                        EventLogEntryType.Warning, 4013);
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
            Exception? lastException = null;

            EventLog.WriteEntry("Application",
                $"[RAW] Inserting: title='{title}' eventTime={eventTimeStr} eventType='{eventType}'",
                EventLogEntryType.Information, 4020);

            for (int attempt = 1; attempt <= maxRetries; attempt++)
            {
                try
                {
                    using var client = CreateGraphClient(accessToken, timeoutSeconds);

                    // ── Idempotency check ──────────────────────────────────────
                    if (await RawRecordAlreadyExistsAsync(client, title, eventTime))
                    {
                        EventLog.WriteEntry("Application",
                            $"[RAW] Idempotency: record already exists for title='{title}' at {eventTimeStr} — skipping insert.",
                            EventLogEntryType.Information, 4021);
                        return;
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

                    if (response.IsSuccessStatusCode)
                    {
                        EventLog.WriteEntry("Application",
                            $"[RAW] Insert success: title='{title}' at {eventTimeStr}",
                            EventLogEntryType.Information, 4022);
                        return;
                    }

                    string responseBody = await response.Content.ReadAsStringAsync();
                    lastException = new InvalidOperationException(
                        $"Raw list insert failed HTTP {(int)response.StatusCode} for {title} at {eventTimeStr}: {responseBody}");

                    EventLog.WriteEntry("Application",
                        $"[RAW] Insert attempt {attempt}/{maxRetries} failed: HTTP {(int)response.StatusCode} — {responseBody}",
                        EventLogEntryType.Warning, 4023);

                    if (attempt < maxRetries) { await Task.Delay(delayMs); delayMs = Math.Min(delayMs * 2, 10000); }
                }
                catch (Exception ex)
                {
                    lastException = ex;
                    EventLog.WriteEntry("Application",
                        $"[RAW] Insert attempt {attempt}/{maxRetries} exception: {ex.GetType().Name}: {ex.Message}",
                        EventLogEntryType.Warning, 4024);
                    if (attempt < maxRetries) { await Task.Delay(delayMs); delayMs = Math.Min(delayMs * 2, 10000); }
                }
            }

            throw new InvalidOperationException(
                $"Failed to write raw event to SharePoint after {maxRetries} attempts. EventId={eventId}, User={username}, Time={eventTimeStr}.",
                lastException);
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

            EventLog.WriteEntry("Application",
                $"[DBG-Summary] UpsertLogin: user={username} computer={computerName} " +
                $"loginTime={loginTime:O} workDate={workDate} summaryKey={summaryKey}",
                EventLogEntryType.Information, 3001);

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

                EventLog.WriteEntry("Application",
                    $"[DBG-Summary] UpsertLogin: row exists itemId={itemId} storedLogin={storedLogin?.ToString("O") ?? "(null)"} incoming={loginTime:O}",
                    EventLogEntryType.Information, 3002);

                if (storedLogin.HasValue && loginTime < storedLogin.Value && !string.IsNullOrWhiteSpace(itemId))
                {
                    EventLog.WriteEntry("Application",
                        $"[DBG-Summary] UpsertLogin: updating to earlier loginTime={loginTime:O}",
                        EventLogEntryType.Information, 3003);

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
                    var patchResponse = await client.SendAsync(patchRequest);
                    if (!patchResponse.IsSuccessStatusCode)
                    {
                        string body = await patchResponse.Content.ReadAsStringAsync();
                        throw new InvalidOperationException(
                            $"Failed to update earlier LoginTime for summary key '{summaryKey}' (item {itemId}). Status={patchResponse.StatusCode} Body={body}");
                    }
                }

                return; // row exists — nothing more to do
            }

            // ── Create new summary row ────────────────────────────────────────────
            EventLog.WriteEntry("Application",
                $"[DBG-Summary] UpsertLogin: creating new row for summaryKey={summaryKey}",
                EventLogEntryType.Information, 3004);

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
            var createResponse = await client.PostAsync(
                $"https://graph.microsoft.com/v1.0/sites/{_siteId}/lists/{_summaryListId}/items",
                createContent);
            if (!createResponse.IsSuccessStatusCode)
            {
                string body = await createResponse.Content.ReadAsStringAsync();
                throw new InvalidOperationException(
                    $"Failed to create summary login row for key '{summaryKey}'. Status={createResponse.StatusCode} Body={body}");
            }

            EventLog.WriteEntry("Application",
                $"[DBG-Summary] UpsertLogin: successfully created row for summaryKey={summaryKey}",
                EventLogEntryType.Information, 3005);
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

            EventLog.WriteEntry("Application",
                $"[DBG-Summary] TryUpdateShutdown: user={username} computer={computerName} " +
                $"shutdownTime={shutdownTime:O} eventId={eventId} eventType='{eventType}'",
                EventLogEntryType.Information, 3010);

            using var client = CreateGraphClient(accessToken, 30);
            var summaryItem = await FindSummaryItemForShutdownAsync(client, computerName, username, shutdownTime);
            if (summaryItem == null)
            {
                EventLog.WriteEntry("Application",
                    $"[DBG-Summary] TryUpdateShutdown: SKIP — no matching summary row for user={username} " +
                    $"computer={computerName} shutdownTime={shutdownTime:O}",
                    EventLogEntryType.Information, 3011);
                return;
            }

            string? itemId  = summaryItem?["id"]?.ToString();
            if (string.IsNullOrWhiteSpace(itemId)) return;

            var fields            = summaryItem?["fields"] as JObject;
            DateTime? loginTime   = ParseFieldDateTime(fields, "LoginTime");
            DateTime? expectedTimeOut = ParseFieldDateTime(fields, "ExpectedTimeOut");
            DateTime? currentShutdown = ParseFieldDateTime(fields, "ShutdownTime");
            string? currentShutdownType = fields?["ShutdownType"]?.ToString();

            EventLog.WriteEntry("Application",
                $"[DBG-Summary] TryUpdateShutdown: found row itemId={itemId} " +
                $"loginTime={loginTime?.ToString("O") ?? "(null)"} " +
                $"expectedTimeOut={expectedTimeOut?.ToString("O") ?? "(null)"} " +
                $"currentShutdown={currentShutdown?.ToString("O") ?? "(null)"} " +
                $"currentType='{currentShutdownType ?? "(empty)"}'",
                EventLogEntryType.Information, 3012);

            if (!IsValidShutdownCandidate(eventId, eventType, shutdownTime, loginTime, expectedTimeOut))
            {
                EventLog.WriteEntry("Application",
                    $"[DBG-Summary] TryUpdateShutdown: SKIP — IsValidShutdownCandidate=false " +
                    $"eventId={eventId} eventType='{eventType}' shutdownTime={shutdownTime:O} " +
                    $"loginTime={loginTime?.ToString("O") ?? "(null)"} expectedTimeOut={expectedTimeOut?.ToString("O") ?? "(null)"}",
                    EventLogEntryType.Information, 3013);
                return;
            }

            int newPriority     = GetShutdownPriority(eventId, eventType);
            int currentPriority = GetPriorityFromShutdownType(currentShutdownType);

            if (newPriority < currentPriority)
            {
                EventLog.WriteEntry("Application",
                    $"[DBG-Summary] TryUpdateShutdown: SKIP — priority too low: new={newPriority} current={currentPriority} " +
                    $"(existing='{currentShutdownType}')",
                    EventLogEntryType.Information, 3014);
                return;
            }

            if (newPriority == currentPriority)
            {
                if (currentShutdown.HasValue && currentShutdown.Value >= shutdownTime)
                {
                    EventLog.WriteEntry("Application",
                        $"[DBG-Summary] TryUpdateShutdown: SKIP — same priority, existing time is later: " +
                        $"existing={currentShutdown.Value:O} incoming={shutdownTime:O}",
                        EventLogEntryType.Information, 3015);
                    return;
                }
            }

            string shutdownTypeStr = BuildShutdownType(eventId, eventType);
            EventLog.WriteEntry("Application",
                $"[DBG-Summary] TryUpdateShutdown: PATCHING itemId={itemId} " +
                $"shutdownTime={shutdownTime:O} shutdownType='{shutdownTypeStr}' priority={newPriority}",
                EventLogEntryType.Information, 3016);

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
            var patchResult = await client.SendAsync(patchRequest);
            if (!patchResult.IsSuccessStatusCode)
            {
                string body = await patchResult.Content.ReadAsStringAsync();
                throw new InvalidOperationException(
                    $"Failed to update summary shutdown for item {itemId} ({eventId}). " +
                    $"Status={patchResult.StatusCode} Body={body}");
            }

            EventLog.WriteEntry("Application",
                $"[DBG-Summary] TryUpdateShutdown: PATCH success itemId={itemId}",
                EventLogEntryType.Information, 3017);
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

                await CleanupListByDateFieldAsync(client, _listId, "EventTime", cutoffDate);

                if (!string.IsNullOrWhiteSpace(_summaryListId))
                    await CleanupListByDateFieldAsync(client, _summaryListId, "WorkDate", cutoffDate);
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("Application",
                    $"Error in cleanup task: {ex.Message}",
                    EventLogEntryType.Warning, 1013);
            }
        }

        // ── Private helpers ───────────────────────────────────────────────────────

        private async Task CleanupListByDateFieldAsync(
            HttpClient client, string listId, string dateField, DateTime cutoffDate)
        {
            string url = $"https://graph.microsoft.com/v1.0/sites/{_siteId}/lists/{listId}/items" +
                         $"?$expand=fields&$select=id,fields&$top=5000";

            var response = await client.GetAsync(url);
            if (!response.IsSuccessStatusCode) return;

            var result = JsonConvert.DeserializeObject<JObject>(await response.Content.ReadAsStringAsync());
            var items = result?["value"] as JArray;
            if (items == null || items.Count == 0) return;

            foreach (JToken item in items)
            {
                try
                {
                    var itemFields = item["fields"] as JObject;
                    string? dateValue = itemFields?[dateField]?.ToString();
                    if (string.IsNullOrWhiteSpace(dateValue))
                        continue;

                    if (!DateTime.TryParse(dateValue, out DateTime parsed))
                        continue;

                    if (parsed >= cutoffDate)
                        continue;

                    string? itemId = item["id"]?.ToString();
                    if (string.IsNullOrWhiteSpace(itemId))
                        continue;

                    await client.DeleteAsync($"https://graph.microsoft.com/v1.0/sites/{_siteId}/lists/{listId}/items/{itemId}");
                    await Task.Delay(200);
                }
                catch
                {
                    // continue deleting remaining items
                }
            }
        }

        private HttpClient CreateGraphClient(string accessToken, int timeoutSeconds)
        {
            var client = new HttpClient { Timeout = TimeSpan.FromSeconds(timeoutSeconds) };
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            return client;
        }

        private async Task<JToken?> FindSummaryItemForShutdownAsync(
            HttpClient client, string computerName, string username, DateTime shutdownTime)
        {
            // Prefer same-day summary row.
            string todayKey = BuildSummaryKey(computerName, username, shutdownTime.ToString("yyyy-MM-dd"));
            var todayItems = await FindSummaryItemAsync(client, todayKey);
            if (todayItems != null && todayItems.Count > 0)
                return todayItems[0];

            // Fallback: previous-day row for overnight sessions.
            string yesterdayKey = BuildSummaryKey(computerName, username, shutdownTime.AddDays(-1).ToString("yyyy-MM-dd"));
            var yesterdayItems = await FindSummaryItemAsync(client, yesterdayKey);
            if (yesterdayItems == null || yesterdayItems.Count == 0)
                return null;

            var item = yesterdayItems[0];
            var fields = item?["fields"] as JObject;
            DateTime? loginTime = ParseFieldDateTime(fields, "LoginTime");
            if (!loginTime.HasValue)
                return null;

            // Accept overnight session up to 20h after login.
            if (shutdownTime >= loginTime.Value && shutdownTime <= loginTime.Value.AddHours(20))
                return item;

            return null;
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

        private async Task<bool> RawRecordAlreadyExistsAsync(HttpClient client, string title, DateTime eventTime)
        {
            string checkUrl = $"https://graph.microsoft.com/v1.0/sites/{_siteId}/lists/{_listId}/items" +
                $"?$expand=fields&$filter=fields/Title eq '{EscapeODataLiteral(title)}'&$top=20";

            var checkResponse = await client.GetAsync(checkUrl);
            if (!checkResponse.IsSuccessStatusCode)
                return false;

            var checkObj = JsonConvert.DeserializeObject<JObject>(
                await checkResponse.Content.ReadAsStringAsync());

            var existing = checkObj?["value"] as JArray;
            if (existing == null || existing.Count == 0)
                return false;

            DateTime eventUtc = eventTime.ToUniversalTime();
            foreach (JToken row in existing)
            {
                var fields = row["fields"] as JObject;
                DateTime? existingTime = ParseFieldDateTime(fields, "EventTime");
                if (!existingTime.HasValue)
                    continue;

                DateTime existingUtc = existingTime.Value.ToUniversalTime();
                // 60-second window: Graph API has eventual consistency so a record
                // inserted moments ago may not appear immediately in query results.
                // A wide window is safe because title already encodes ComputerName+EventId+Username.
                if (Math.Abs((existingUtc - eventUtc).TotalSeconds) <= 60)
                {
                    EventLog.WriteEntry("Application",
                        $"[RAW] Idempotency hit: title='{title}' existing={existingUtc:O} incoming={eventUtc:O} " +
                        $"diff={(existingUtc - eventUtc).TotalSeconds:F1}s",
                        EventLogEntryType.Information, 4025);
                    return true;
                }
            }

            return false;
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
        ///   • 6006 unconfirmed (no paired 1074 shutdown) → treated like 4647, only accepted
        ///     within ±5h of expectedTimeOut, because we can't tell if it was a restart.
        ///   • 6006 confirmed shutdown (paired 1074 was power-off/shutdown) → always accepted.
        ///   • 4647 (User Logout) → only accepted if within ±5h of expectedTimeOut.
        ///   • 6008/41 (Unexpected Shutdown/Crash) → only accepted at or after expectedTimeOut.
        /// </summary>
        private static bool IsValidShutdownCandidate(
            int eventId, string eventType,
            DateTime shutdownTime,
            DateTime? loginTime, DateTime? expectedTimeOut)
        {
            // 1074 Restart is never a final shutdown
            if (eventId == 1074 && IsRestartEventType(eventType))
                return false;

            DateTime refExpected = expectedTimeOut
                ?? (loginTime?.AddHours(9) ?? shutdownTime.AddHours(-1));

            // Guardrail: shutdown must belong to the same work session window.
            if (loginTime.HasValue)
            {
                if (shutdownTime < loginTime.Value)
                    return false;

                if (shutdownTime > loginTime.Value.AddHours(20))
                    return false;
            }

            // Unexpected shutdown/crash: only count if it happened at or after expected time out
            if (eventId == 6008 || eventId == 41)
                return shutdownTime >= refExpected;

            // User logout: accept if within ±5h of expectedTimeOut (allow early leave/overtime)
            if (eventId == 4647)
                return shutdownTime >= refExpected.AddHours(-5) &&
                       shutdownTime <= refExpected.AddHours(5);

            // 6006 unconfirmed (eventType contains "unconfirmed"): apply same time window as 4647
            // because we don't know if this was a restart or shutdown.
            if (eventId == 6006 && IsUnconfirmed6006(eventType))
                return shutdownTime >= refExpected.AddHours(-5) &&
                       shutdownTime <= refExpected.AddHours(5);

            // 6006 confirmed shutdown, and 1074 non-restart: valid within session guardrail above.
            return true;
        }

        /// <summary>
        /// Priority for Summary ShutdownTime. Higher value wins.
        ///   6006 confirmed shutdown = 5  (paired 1074 was power-off/shutdown)
        ///   1074 Shutdown           = 4  (confirmed power-off, no 6006 yet)
        ///   6006 unconfirmed        = 3  (no paired 1074 — could be restart, treated cautiously)
        ///   4647 User Logout        = 2
        ///   6008 Unexpected         = 1
        ///   41   Crash              = 1
        /// </summary>
        private static int GetShutdownPriority(int eventId, string eventType)
        {
            if (eventId == 6006)
                return IsUnconfirmed6006(eventType) ? 3 : 5;

            if (eventId == 1074 && !IsRestartEventType(eventType)) return 4;
            if (eventId == 4647) return 2;
            if (eventId == 6008) return 1;
            if (eventId == 41)   return 1;
            return 0;
        }

        /// <summary>Returns true if the eventType string indicates a restart (case-insensitive).</summary>
        private static bool IsRestartEventType(string eventType)
            => eventType.Contains("restart", StringComparison.OrdinalIgnoreCase) ||
               eventType.Contains("reboot", StringComparison.OrdinalIgnoreCase);

        /// <summary>Returns true if this 6006 event has no confirmed paired 1074 shutdown type.</summary>
        private static bool IsUnconfirmed6006(string eventType)
            => eventType.Contains("unconfirmed", StringComparison.OrdinalIgnoreCase);

        private static int GetPriorityFromShutdownType(string? shutdownType)
        {
            if (string.IsNullOrWhiteSpace(shutdownType)) return 0;
            // Format stored: "6006 - Shutdown Completed (Shutdown Initiated)"
            //             or "6006 - Shutdown Completed (type unconfirmed)"
            //             or "1074 - Restart Initiated"  etc.
            string[] parts = shutdownType.Split('-', 2, StringSplitOptions.TrimEntries);
            if (parts.Length == 0 || !int.TryParse(parts[0], out int existingEventId)) return 0;
            string existingEventType = parts.Length > 1 ? parts[1] : string.Empty;
            return GetShutdownPriority(existingEventId, existingEventType);
        }
    }

}
