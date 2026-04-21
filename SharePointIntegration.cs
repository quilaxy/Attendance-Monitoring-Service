using System;
using System.Collections.Generic;
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
        private static Task? _networkWarmupTask;
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
                SafeWriteEventLog("Application",
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
            Task? networkWarmupTask = null;

            lock (_networkWaitLock)
            {
                bool inShutdownWindow = (DateTime.Now - _lastShutdownEventTime) < ShutdownEventWindow;

                if (!_hasWaitedForNetwork)
                {
                    if (isShutdownEvent || inShutdownWindow)
                    {
                    }
                    else
                    {
                        SafeWriteEventLog("Application",
                            "[TOKEN] Waiting 30s for network on fresh boot...",
                            EventLogEntryType.Information, 4010);
                        _networkWarmupTask ??= Task.Delay(TimeSpan.FromSeconds(30));
                        networkWarmupTask = _networkWarmupTask;
                    }

                    _hasWaitedForNetwork = true;
                }
                else if (_networkWarmupTask != null && !_networkWarmupTask.IsCompleted)
                {
                    networkWarmupTask = _networkWarmupTask;
                }
            }

            if (networkWarmupTask != null)
                await networkWarmupTask;

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
                    SafeWriteEventLog("Application",
                        $"[TOKEN] Attempt {attempt}/{maxRetries} failed: HTTP {(int)response.StatusCode} — {errorBody}",
                        EventLogEntryType.Warning, 4011);

                    if (attempt < maxRetries) { await Task.Delay(delayMs); delayMs *= 2; }
                    else throw new Exception($"Failed to get access token after {maxRetries} attempts. Last status: {(int)response.StatusCode}");
                }
                catch (HttpRequestException ex) when (ex.InnerException is SocketException)
                {
                    SafeWriteEventLog("Application",
                        $"[TOKEN] Attempt {attempt}/{maxRetries} network error: {ex.Message}",
                        EventLogEntryType.Warning, 4012);
                    if (attempt < maxRetries) { await Task.Delay(delayMs); delayMs *= 2; }
                    else throw;
                }
                catch (Exception ex)
                {
                    SafeWriteEventLog("Application",
                        $"[TOKEN] Attempt {attempt}/{maxRetries} exception: {ex.GetType().Name}: {ex.Message}",
                        EventLogEntryType.Warning, 4013);
                    if (attempt < maxRetries) { await Task.Delay(delayMs); delayMs *= 2; }
                    else throw;
                }
            }

            return null;
        }

        public async Task<string?> GetLatestUsernameByComputerAsync(string computerName, DateTime referenceTime)
        {
            var result = await GetLatestUsernameByComputerWithStatusAsync(computerName, referenceTime);
            return result.Username;
        }

        public async Task<(string? Username, bool NetworkUnavailable)> GetLatestUsernameByComputerWithStatusAsync(
            string computerName, DateTime referenceTime)
        {
            try
            {
                string? accessToken = await GetAccessTokenAsync(referenceTime, 0);
                if (string.IsNullOrWhiteSpace(accessToken))
                    return (null, true);

                using var client = CreateGraphClient(accessToken, timeoutSeconds: 30);
                string filter = $"fields/ComputerName eq '{EscapeODataLiteral(computerName)}'";
                string url = $"https://graph.microsoft.com/v1.0/sites/{_siteId}/lists/{_listId}/items" +
                             $"?$expand=fields&$filter={Uri.EscapeDataString(filter)}&$top=50";

                var request = new HttpRequestMessage(HttpMethod.Get, url);
                var response = await client.SendAsync(request);
                if (!response.IsSuccessStatusCode)
                    return (null, false);

                var payload = JsonConvert.DeserializeObject<JObject>(await response.Content.ReadAsStringAsync());
                var items = payload?["value"] as JArray;
                if (items == null || items.Count == 0)
                    return (null, false);

                var latest = items
                    .Select(x => new
                    {
                        Username = x["fields"]?["Username"]?.ToString(),
                        EventTime = ParseFieldDateTime(x["fields"] as JObject, "EventTime")
                    })
                    .Where(x => !string.IsNullOrWhiteSpace(x.Username) && x.EventTime.HasValue)
                    .OrderByDescending(x => x.EventTime!.Value)
                    .FirstOrDefault();

                return (latest?.Username, false);
            }
            catch (HttpRequestException)
            {
                return (null, true);
            }
            catch (TaskCanceledException)
            {
                return (null, true);
            }
            catch (Exception ex)
            {
                SafeWriteEventLog("Application",
                    $"[6005-FALLBACK] GetLatestUsernameByComputerAsync failed for '{computerName}': {ex.Message}",
                    EventLogEntryType.Warning, 3023);
                return (null, false);
            }
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

            string eventTimeStr = ToUtcString(eventTime);
            string title        = $"{computerName}\\{eventId}\\{username}";
            Exception? lastException = null;

            SafeWriteEventLog("Application",
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
                        SafeWriteEventLog("Application",
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
                        SafeWriteEventLog("Application",
                            $"[RAW] Insert success: title='{title}' at {eventTimeStr}",
                            EventLogEntryType.Information, 4022);
                        return;
                    }

                    string responseBody = await response.Content.ReadAsStringAsync();
                    lastException = new InvalidOperationException(
                        $"Raw list insert failed HTTP {(int)response.StatusCode} for {title} at {eventTimeStr}: {responseBody}");

                    SafeWriteEventLog("Application",
                        $"[RAW] Insert attempt {attempt}/{maxRetries} failed: HTTP {(int)response.StatusCode} — {responseBody}",
                        EventLogEntryType.Warning, 4023);

                    if (attempt < maxRetries) { await Task.Delay(delayMs); delayMs = Math.Min(delayMs * 2, 10000); }
                }
                catch (Exception ex)
                {
                    lastException = ex;
                    SafeWriteEventLog("Application",
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
        /// Creates (or keeps existing) a daily summary row for the given user+workDate.
        ///
        /// Rules:
        ///   • Only ONE summary row per (Username, WorkDate).
        ///   • If the row already exists, do NOT update LoginTime — we always keep the earliest
        ///     login recorded. The earliest login was set when the row was first created.
        ///   • If the row does not exist, create it now.
        /// </summary>
        public async Task UpsertDailySummaryLoginAsync(
            string accessToken, string username, string computerName, DateTime loginTime,
            SummaryCache? summaryCache = null,
            string? status = null)
        {
            if (string.IsNullOrWhiteSpace(_summaryListId)) return;

            string workDate    = loginTime.ToLocalTime().ToString("yyyy-MM-dd");
            string summaryKey  = BuildSummaryKey(username, workDate);
            DateTime expectedTimeOut = loginTime.AddHours(9);

            SafeWriteEventLog("Application",
                $"[DBG-Summary] UpsertLogin: user={username} computer={computerName} " +
                $"loginTime={loginTime:O} workDate={workDate} summaryKey={summaryKey}",
                EventLogEntryType.Information, 3001);

            // ── Cache check: kalau summaryKey sudah ada di cache lokal, row pasti
            // sudah ada di SharePoint — skip query sama sekali.
            if (summaryCache != null && await summaryCache.ContainsAsync(summaryKey))
            {
                SafeWriteEventLog("Application",
                    $"[DBG-Summary] UpsertLogin: cache hit — row already exists for summaryKey={summaryKey}, skipping",
                    EventLogEntryType.Information, 3007);
                return;
            }

            using var client = CreateGraphClient(accessToken, 60);
            var existingItems = await FindSummaryItemWithRetryAsync(client, summaryKey);

            if (existingItems != null && existingItems.Count > 0)
            {
                // Pilih row dengan LoginTime paling awal sebagai row canonical.
                // Kalau ada duplikat (dari bug lama), hapus yang lain.
                JToken? canonical = null;
                DateTime? canonicalLogin = null;

                foreach (var candidate in existingItems)
                {
                    var cFields = candidate["fields"] as JObject;
                    DateTime? cLogin = ParseFieldDateTime(cFields, "LoginTime");
                    if (canonical == null || (cLogin.HasValue && (!canonicalLogin.HasValue || cLogin.Value < canonicalLogin.Value)))
                    {
                        canonical = candidate;
                        canonicalLogin = cLogin;
                    }
                }

                // Hapus duplikat (kalau ada lebih dari 1 row)
                if (existingItems.Count > 1)
                {
                    foreach (var dup in existingItems)
                    {
                        string? dupId = dup["id"]?.ToString();
                        if (dupId == canonical?["id"]?.ToString() || string.IsNullOrWhiteSpace(dupId))
                            continue;

                        SafeWriteEventLog("Application",
                            $"[DBG-Summary] UpsertLogin: deleting duplicate row itemId={dupId} summaryKey={summaryKey}",
                            EventLogEntryType.Warning, 3006);

                        using var delRequest = new HttpRequestMessage(HttpMethod.Delete,
                            $"https://graph.microsoft.com/v1.0/sites/{_siteId}/lists/{_summaryListId}/items/{dupId}");
                        await client.SendAsync(delRequest); // best-effort, ignore failure
                    }
                }

                string? itemId = canonical?["id"]?.ToString();
                var fields = canonical?["fields"] as JObject;
                DateTime? storedLogin = ParseFieldDateTime(fields, "LoginTime");
                string? storedStatus = fields?["Status"]?.ToString();

                SafeWriteEventLog("Application",
                    $"[DBG-Summary] UpsertLogin: row exists itemId={itemId} storedLogin={storedLogin?.ToString("O") ?? "(null)"} incoming={loginTime:O} totalFound={existingItems.Count}",
                    EventLogEntryType.Information, 3002);

                // Update ke loginTime yang lebih awal kalau perlu
                if (storedLogin.HasValue && loginTime < storedLogin.Value && !string.IsNullOrWhiteSpace(itemId))
                {
                    SafeWriteEventLog("Application",
                        $"[DBG-Summary] UpsertLogin: updating to earlier loginTime={loginTime:O}",
                        EventLogEntryType.Information, 3003);

                    var updateData = new
                    {
                        fields = new
                        {
                            LoginTime        = ToUtcString(loginTime),
                            ExpectedTimeOut  = ToUtcString(loginTime.AddHours(9)),
                            ClockIn          = ToLocalTimeString(loginTime),
                            ExpectedClockOut = ToLocalTimeString(loginTime.AddHours(9))
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

                if (!string.IsNullOrWhiteSpace(itemId) &&
                    !string.IsNullOrWhiteSpace(status) &&
                    !string.Equals(storedStatus, status, StringComparison.OrdinalIgnoreCase))
                {
                    var statusPatch = new JObject
                    {
                        ["Status"] = status
                    };
                    var statusPatchContent = new StringContent(
                        statusPatch.ToString(Newtonsoft.Json.Formatting.None), Encoding.UTF8, "application/json");
                    using var statusPatchRequest = new HttpRequestMessage(new HttpMethod("PATCH"),
                        $"https://graph.microsoft.com/v1.0/sites/{_siteId}/lists/{_summaryListId}/items/{itemId}/fields")
                    { Content = statusPatchContent };
                    var statusPatchResponse = await client.SendAsync(statusPatchRequest);
                    if (!statusPatchResponse.IsSuccessStatusCode)
                    {
                        string body = await statusPatchResponse.Content.ReadAsStringAsync();
                        throw new InvalidOperationException(
                            $"Failed to update summary Status for key '{summaryKey}' (item {itemId}). " +
                            $"Status={statusPatchResponse.StatusCode} Body={body}");
                    }
                }

                // Tulis ke cache: row sudah confirmed ada di SharePoint
                if (summaryCache != null)
                    await summaryCache.AddAsync(summaryKey);

                return; // row exists — nothing more to do
            }

            // ── Create new summary row ────────────────────────────────────────────
            SafeWriteEventLog("Application",
                $"[DBG-Summary] UpsertLogin: creating new row for summaryKey={summaryKey}",
                EventLogEntryType.Information, 3004);

            var fieldsData = new JObject
            {
                ["Title"] = summaryKey,
                ["Username"] = username,
                ["ComputerName"] = computerName,
                ["WorkDate"] = workDate,
                ["LoginTime"] = ToUtcString(loginTime),
                ["ExpectedTimeOut"] = ToUtcString(expectedTimeOut),
                ["ClockIn"] = ToLocalTimeString(loginTime),
                ["ExpectedClockOut"] = ToLocalTimeString(expectedTimeOut),
                ["ClockOut"] = null,
                ["ShutdownType"] = string.Empty
            };
            if (!string.IsNullOrWhiteSpace(status))
                fieldsData["Status"] = status;

            var postData = new JObject
            {
                ["fields"] = fieldsData
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

            SafeWriteEventLog("Application",
                $"[DBG-Summary] UpsertLogin: successfully created row for summaryKey={summaryKey}",
                EventLogEntryType.Information, 3005);

            // Tulis ke cache setelah row berhasil di-create di SharePoint
            if (summaryCache != null)
                await summaryCache.AddAsync(summaryKey);
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
        ///   • Tidak ada validasi jam khusus (expected timeout/session guardrail).
        ///     Event shutdown valid akan langsung diproses, lalu aturan latest/priority
        ///     menentukan apakah overwrite diperlukan.
        ///   • 1074 Restart tetap dikecualikan (bukan final shutdown).
        /// </summary>
        public async Task TryUpdateDailySummaryShutdownAsync(
            string accessToken, string username, string computerName,
            DateTime shutdownTime, int eventId, string eventType,
            SummaryCache? summaryCache = null)
        {
            if (string.IsNullOrWhiteSpace(_summaryListId)) return;

            SafeWriteEventLog("Application",
                $"[DBG-Summary] TryUpdateShutdown: user={username} computer={computerName} " +
                $"shutdownTime={shutdownTime:O} eventId={eventId} eventType='{eventType}'",
                EventLogEntryType.Information, 3010);

            using var client = CreateGraphClient(accessToken, 90); // 90s — retry bisa butuh ~21s
            var summaryItem = await FindSummaryItemForShutdownAsync(client, computerName, username, shutdownTime, summaryCache);
            if (summaryItem == null)
            {
                SafeWriteEventLog("Application",
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

            SafeWriteEventLog("Application",
                $"[DBG-Summary] TryUpdateShutdown: found row itemId={itemId} " +
                $"loginTime={loginTime?.ToString("O") ?? "(null)"} " +
                $"expectedTimeOut={expectedTimeOut?.ToString("O") ?? "(null)"} " +
                $"currentShutdown={currentShutdown?.ToString("O") ?? "(null)"} " +
                $"currentType='{currentShutdownType ?? "(empty)"}' " +
                $"allFields={fields?.ToString(Newtonsoft.Json.Formatting.None) ?? "(null)"}",
                EventLogEntryType.Information, 3012);

            if (!IsValidShutdownCandidate(eventId, eventType, shutdownTime, loginTime, expectedTimeOut))
            {
                SafeWriteEventLog("Application",
                    $"[DBG-Summary] TryUpdateShutdown: SKIP — restart event is excluded " +
                    $"eventId={eventId} eventType='{eventType}' shutdownTime={shutdownTime:O}",
                    EventLogEntryType.Information, 3013);
                return;
            }

            int newPriority     = GetShutdownPriority(eventId, eventType);
            int currentPriority = GetPriorityFromShutdownType(currentShutdownType);

            // FIX [NEW-SESSION]: Kalau shutdown baru terjadi SETELAH shutdown yang tersimpan,
            // artinya user sudah login lagi (sesi baru) lalu shutdown lagi.
            // Dalam kasus ini, abaikan priority lama — shutdown terbaru selalu lebih relevan.
            // Contoh: 6006 jam 09:00 (priority 5) lalu login jam 13:00 lalu 4647 jam 17:00 (priority 2)
            // → tanpa fix: 4647 di-skip karena priority lebih rendah, ShutdownTime tetap 09:00 ❌
            // → dengan fix: 4647 jam 17:00 > 6006 jam 09:00 → reset priority, tulis 17:00 ✅
            bool isNewSession = currentShutdown.HasValue && shutdownTime > currentShutdown.Value;
            if (isNewSession)
            {
                SafeWriteEventLog("Application",
                    $"[DBG-Summary] TryUpdateShutdown: NEW SESSION detected — " +
                    $"incoming shutdownTime ({shutdownTime:O}) > existing ({currentShutdown!.Value:O}). " +
                    $"Resetting priority comparison. new={newPriority} old={currentPriority}",
                    EventLogEntryType.Information, 3018);

                // Sesi baru → tulis langsung tanpa cek priority lama.
                // ShutdownTime yang lebih baru sudah pasti lebih relevan untuk absensi.
            }
            else
            {
                // Sesi yang sama — terapkan priority system normal.
                if (newPriority < currentPriority)
                {
                    SafeWriteEventLog("Application",
                        $"[DBG-Summary] TryUpdateShutdown: SKIP — priority too low: new={newPriority} current={currentPriority} " +
                        $"(existing='{currentShutdownType}')",
                        EventLogEntryType.Information, 3014);
                    return;
                }

                if (newPriority == currentPriority)
                {
                    if (currentShutdown.HasValue && currentShutdown.Value >= shutdownTime)
                    {
                        SafeWriteEventLog("Application",
                            $"[DBG-Summary] TryUpdateShutdown: SKIP — same priority, existing time is later: " +
                            $"existing={currentShutdown.Value:O} incoming={shutdownTime:O}",
                            EventLogEntryType.Information, 3015);
                        return;
                    }
                }
            }

            string shutdownTypeStr = BuildShutdownType(eventId, eventType);
            SafeWriteEventLog("Application",
                $"[DBG-Summary] TryUpdateShutdown: PATCHING itemId={itemId} " +
                $"shutdownTime={shutdownTime:O} shutdownType='{shutdownTypeStr}' " +
                $"priority={newPriority} isNewSession={isNewSession}",
                EventLogEntryType.Information, 3016);

            // PATCH ke /items/{id}/fields — body langsung berisi field values tanpa "fields" wrapper
            var patchBody = new JObject
            {
                ["ShutdownTime"] = ToUtcString(shutdownTime),
                ["ClockOut"] = ToLocalTimeString(shutdownTime),
                ["ShutdownType"] = shutdownTypeStr,
                ["ComputerName"] = computerName
            };

            string patchJson = patchBody.ToString(Newtonsoft.Json.Formatting.None);
            SafeWriteEventLog("Application",
                $"[DBG-Summary] TryUpdateShutdown: PATCH body={patchJson}",
                EventLogEntryType.Information, 3022);

            var patchContent = new StringContent(patchJson, Encoding.UTF8, "application/json");
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

            SafeWriteEventLog("Application",
                $"[DBG-Summary] TryUpdateShutdown: PATCH success itemId={itemId}",
                EventLogEntryType.Information, 3017);
        }

        // ── Cleanup ───────────────────────────────────────────────────────────────

        public async Task CleanupOldRecordsAsync(int retentionMonths = 6)
        {
            try
            {
                string? accessToken = await GetAccessTokenAsync(DateTime.Now, 0);
                if (string.IsNullOrEmpty(accessToken))
                {
                    SafeWriteEventLog("Application",
                        $"[CLEANUP] Skipped — could not obtain access token.",
                        EventLogEntryType.Warning, 5001);
                    return;
                }

                DateTime cutoffDate = DateTime.Now.AddMonths(-retentionMonths);

                SafeWriteEventLog("Application",
                    $"[CLEANUP] Started — cutoffDate={cutoffDate:yyyy-MM-dd} retentionMonths={retentionMonths} " +
                    $"listId='{_listId}' summaryListId='{_summaryListId ?? "(none)"}'",
                    EventLogEntryType.Information, 5001);

                using var client = new HttpClient { Timeout = TimeSpan.FromMinutes(5) };
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                client.DefaultRequestHeaders.Add("Prefer", "HonorNonIndexedQueriesWarningMayFailRandomly");

                int rawDeleted = await CleanupListByDateFieldAsync(client, _listId, "EventTime", cutoffDate);
                SafeWriteEventLog("Application",
                    $"[CLEANUP] ListId (raw) done — {rawDeleted} items deleted. cutoffDate={cutoffDate:yyyy-MM-dd}",
                    EventLogEntryType.Information, 5002);

                if (!string.IsNullOrWhiteSpace(_summaryListId))
                {
                    int summaryDeleted = await CleanupListByDateFieldAsync(client, _summaryListId, "WorkDate", cutoffDate);
                    SafeWriteEventLog("Application",
                        $"[CLEANUP] SummaryListId done — {summaryDeleted} items deleted. cutoffDate={cutoffDate:yyyy-MM-dd}",
                        EventLogEntryType.Information, 5003);
                }
            }
            catch (Exception ex)
            {
                SafeWriteEventLog("Application",
                    $"[CLEANUP] Error in cleanup task: {ex.Message}",
                    EventLogEntryType.Warning, 1013);
            }
        }

        // ── Private helpers ───────────────────────────────────────────────────────

        private async Task<int> CleanupListByDateFieldAsync(
            HttpClient client, string listId, string dateField, DateTime cutoffDate)
        {
            int deletedCount = 0;
            int totalFetched = 0;

            string? url = $"https://graph.microsoft.com/v1.0/sites/{_siteId}/lists/{listId}/items" +
                          $"?$expand=fields&$select=id,fields&$top=5000";

            while (!string.IsNullOrWhiteSpace(url))
            {
                var response = await client.GetAsync(url);
                if (!response.IsSuccessStatusCode)
                {
                    SafeWriteEventLog("Application",
                        $"[CLEANUP] Failed to fetch items from listId='{listId}' — " +
                        $"HTTP {(int)response.StatusCode}",
                        EventLogEntryType.Warning, 5004);
                    SafeWriteEventLog("Application",
                        $"[CLEANUP] listId='{listId}' partial progress: fetched={totalFetched}, deleted={deletedCount}.",
                        EventLogEntryType.Warning, 5005);
                    return deletedCount;
                }

                var result = JsonConvert.DeserializeObject<JObject>(await response.Content.ReadAsStringAsync());
                var items = result?["value"] as JArray;
                if (items != null)
                {
                    totalFetched += items.Count;
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

                            var deleteResponse = await client.DeleteAsync(
                                $"https://graph.microsoft.com/v1.0/sites/{_siteId}/lists/{listId}/items/{itemId}");

                            if (deleteResponse.IsSuccessStatusCode)
                            {
                                deletedCount++;
                            }
                            else if (deleteResponse.StatusCode == System.Net.HttpStatusCode.NotFound)
                            {
                                // 404 = sudah dihapus PC lain duluan — normal kalau cleanup jalan bersamaan
                            }
                            else
                            {
                                SafeWriteEventLog("Application",
                                    $"[CLEANUP] Failed to delete itemId='{itemId}' from listId='{listId}' — " +
                                    $"HTTP {(int)deleteResponse.StatusCode}",
                                    EventLogEntryType.Warning, 5005);
                            }

                            await Task.Delay(200);
                        }
                        catch (Exception ex)
                        {
                            string? itemId = item["id"]?.ToString() ?? "(unknown)";
                            SafeWriteEventLog("Application",
                                $"[CLEANUP] Exception deleting itemId='{itemId}' from listId='{listId}': " +
                                $"{ex.GetType().Name}: {ex.Message}",
                                EventLogEntryType.Warning, 5005);
                            // continue deleting remaining items
                        }
                    }
                }

                url = result?["@odata.nextLink"]?.ToString();
            }

            if (totalFetched == 0)
            {
                SafeWriteEventLog("Application",
                    $"[CLEANUP] listId='{listId}' — no items found, nothing to delete.",
                    EventLogEntryType.Information, 5002);
                return 0;
            }

            SafeWriteEventLog("Application",
                $"[CLEANUP] listId='{listId}' — {totalFetched} total items fetched, " +
                $"scanned for {dateField} < {cutoffDate:yyyy-MM-dd}",
                EventLogEntryType.Information, 5001);

            return deletedCount;
        }

        /// <summary>
        /// Converts a local DateTime to UTC and formats as ISO 8601 with Z suffix.
        /// SharePoint Graph API accepts this format and auto-converts for display
        /// based on the site's Regional Settings timezone (e.g. UTC+7).
        /// </summary>
        private static string ToUtcString(DateTime dt)
            => dt.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ");

        /// <summary>
        /// Converts a DateTime to local time and formats only the clock part (HH:mm:ss)
        /// for string-based SharePoint display columns.
        /// Local time here follows the server/host OS timezone where this service runs.
        /// </summary>
        private static string ToLocalTimeString(DateTime dt)
            => dt.ToLocalTime().ToString("HH:mm:ss");

        private HttpClient CreateGraphClient(string accessToken, int timeoutSeconds)
        {
            var client = new HttpClient { Timeout = TimeSpan.FromSeconds(timeoutSeconds) };
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            return client;
        }

        /// <summary>
        /// Never throws — safe to call from any context including shutdown and crash handlers.
        /// Mirrors the same helper in LoginLogoutMonitorService.
        /// Direct EventLog.WriteEntry can throw SecurityException (source not registered)
        /// or InvalidOperationException (EventLog service shutting down) — both would cause
        /// unhandled exceptions on background threads, contributing to 0xe0434352 crashes.
        /// </summary>
        private static void SafeWriteEventLog(string source, string message, EventLogEntryType type, int eventId)
        {
            // Kalau VerboseLogging=false, skip event ID yang masuk kategori verbose.
            if (!LoginLogoutMonitorService.VerboseLogging && _verboseOnlyEventIds.Contains(eventId))
                return;

            try
            {
                EventLog.WriteEntry(source, message, type, eventId);
            }
            catch
            {
                // Suppress all EventLog failures silently.
            }
        }

        /// <summary>
        /// Event ID yang hanya ditulis saat VerboseLogging=true.
        /// </summary>
        private static readonly HashSet<int> _verboseOnlyEventIds = new HashSet<int>
        {
            // SharePoint summary detail
            3001, 3002, 3003, 3004, 3005, 3007, 3008,
            3010, 3011, 3012, 3013, 3014, 3015, 3016, 3017, 3018, 3021, 3022,
            // Dispatch & raw detail
            4010, 4020, 4021, 4022, 4025,
            // Cleanup progress
            5001, 5002, 5003,
        };

        private async Task<JToken?> FindSummaryItemForShutdownAsync(
            HttpClient client, string computerName, string username, DateTime shutdownTime,
            SummaryCache? summaryCache = null)
        {
            // Prefer same-day summary row. Pakai retry karena shutdown bisa di-dispatch
            // sebelum login row ter-index di SharePoint (eventual consistency).
            string todayKey = BuildSummaryKey(username, shutdownTime.ToLocalTime().ToString("yyyy-MM-dd"));

            // Kalau key ada di cache, row pasti ada — tapi tetap fetch untuk ambil itemId dan fields.
            // Pakai retry penuh kalau tidak di cache, retry lebih agresif kalau di cache
            // (kemungkinan besar langsung ketemu).
            bool inCache = summaryCache != null && await summaryCache.ContainsAsync(todayKey);
            var todayItems = inCache
                ? await FindSummaryItemAsync(client, todayKey)          // cache hint: cukup 1 attempt
                : await FindSummaryItemWithRetryAsync(client, todayKey); // tidak di cache: retry penuh

            // Kalau 1 attempt gagal tapi cache bilang ada, coba retry juga
            if (inCache && (todayItems == null || todayItems.Count == 0))
            {
                SafeWriteEventLog("Application",
                    $"[DBG-Summary] FindSummaryItemForShutdown: cache hit but not found on first attempt, retrying key={todayKey}",
                    EventLogEntryType.Warning, 3019);
                todayItems = await FindSummaryItemWithRetryAsync(client, todayKey);
            }

            if (todayItems != null && todayItems.Count > 0)
                return SelectCanonicalSummaryRow(todayItems);

            // Fallback: previous-day row for overnight sessions.
            string yesterdayKey = BuildSummaryKey(username, shutdownTime.ToLocalTime().AddDays(-1).ToString("yyyy-MM-dd"));
            bool yesterdayInCache = summaryCache != null && await summaryCache.ContainsAsync(yesterdayKey);
            var yesterdayItems = yesterdayInCache
                ? await FindSummaryItemAsync(client, yesterdayKey)
                : await FindSummaryItemWithRetryAsync(client, yesterdayKey);

            if (yesterdayInCache && (yesterdayItems == null || yesterdayItems.Count == 0))
                yesterdayItems = await FindSummaryItemWithRetryAsync(client, yesterdayKey);

            if (yesterdayItems == null || yesterdayItems.Count == 0)
                return null;

            return SelectCanonicalSummaryRow(yesterdayItems);
        }

        /// <summary>
        /// Pilih row canonical untuk user+workDate: LoginTime paling awal (lintas device).
        /// Jika LoginTime null, row itu hanya dipilih kalau belum ada kandidat lebih baik.
        /// </summary>
        private static JToken? SelectCanonicalSummaryRow(JArray items)
        {
            JToken? canonical = null;
            DateTime? canonicalLogin = null;

            foreach (var candidate in items)
            {
                var fields = candidate["fields"] as JObject;
                DateTime? cLogin = ParseFieldDateTime(fields, "LoginTime");

                if (canonical == null)
                {
                    canonical = candidate;
                    canonicalLogin = cLogin;
                    continue;
                }

                if (cLogin.HasValue && (!canonicalLogin.HasValue || cLogin.Value < canonicalLogin.Value))
                {
                    canonical = candidate;
                    canonicalLogin = cLogin;
                }
            }

            return canonical;
        }

        private async Task<JArray?> FindSummaryItemAsync(HttpClient client, string summaryKey)
        {
            // summaryKey format: "Username\yyyy-MM-dd"
            // Tidak bisa filter by Title langsung karena backslash (\) di OData filter
            // menyebabkan HTTP 400. Ganti ke filter Username + WorkDate.
            string[] parts = summaryKey.Split('\\');
            if (parts.Length < 2)
            {
                SafeWriteEventLog("Application",
                    $"[DBG-Summary] FindSummaryItemAsync: invalid summaryKey format: {summaryKey}",
                    EventLogEntryType.Warning, 3020);
                return null;
            }
            string username = parts[0];
            string workDate = parts[1];

            string filter = $"fields/Username eq '{EscapeODataLiteral(username)}' and " +
                            $"fields/WorkDate eq '{EscapeODataLiteral(workDate)}'";

            string findUrl = $"https://graph.microsoft.com/v1.0/sites/{_siteId}/lists/{_summaryListId}/items" +
                $"?$expand=fields&$filter={Uri.EscapeDataString(filter)}&$top=5";

            var request = new HttpRequestMessage(HttpMethod.Get, findUrl);
            request.Headers.Add("Prefer", "HonorNonIndexedQueriesWarningMayFailRandomly");
            var findResponse = await client.SendAsync(request);
            if (!findResponse.IsSuccessStatusCode)
            {
                string errBody = await findResponse.Content.ReadAsStringAsync();
                SafeWriteEventLog("Application",
                    $"[DBG-Summary] FindSummaryItemAsync: HTTP {(int)findResponse.StatusCode} for key={summaryKey} body={errBody}",
                    EventLogEntryType.Warning, 3020);
                return null;
            }

            string body = await findResponse.Content.ReadAsStringAsync();
            var findObject = JsonConvert.DeserializeObject<JObject>(body);
            var result = findObject?["value"] as JArray;

            SafeWriteEventLog("Application",
                $"[DBG-Summary] FindSummaryItemAsync: key={summaryKey} count={result?.Count ?? 0}",
                EventLogEntryType.Information, 3021);

            return result;
        }

        /// <summary>
        /// FindSummaryItemAsync dengan retry — untuk UpsertDailySummaryLoginAsync yang butuh
        /// kepastian row tidak ada sebelum create baru. Graph API eventual consistency bisa
        /// menyebabkan row yang baru di-insert belum muncul di query berikutnya.
        /// Retry 3x dengan delay 3s, 6s, 12s (total max ~21 detik).
        /// </summary>
        private async Task<JArray?> FindSummaryItemWithRetryAsync(HttpClient client, string summaryKey)
        {
            int[] delaysMs = { 3000, 6000, 12000 };

            for (int attempt = 0; attempt <= delaysMs.Length; attempt++)
            {
                var result = await FindSummaryItemAsync(client, summaryKey);
                if (result != null && result.Count > 0)
                    return result;

                if (attempt < delaysMs.Length)
                {
                    SafeWriteEventLog("Application",
                        $"[DBG-Summary] FindSummaryItemWithRetry: attempt={attempt + 1} not found for key={summaryKey}, retrying in {delaysMs[attempt]}ms",
                        EventLogEntryType.Information, 3008);
                    await Task.Delay(delaysMs[attempt]);
                }
            }

            SafeWriteEventLog("Application",
                $"[DBG-Summary] FindSummaryItemWithRetry: all attempts exhausted for key={summaryKey}",
                EventLogEntryType.Warning, 3009);
            return null;
        }

        private async Task<bool> RawRecordAlreadyExistsAsync(HttpClient client, string title, DateTime eventTime)
        {
            // Title mengandung backslash → OData filter HTTP 400.
            // Filter pakai EventTime window saja — sudah cukup unik karena
            // title (ComputerName+EventId+Username) di-check dari hasil query.
            DateTime from = eventTime.ToUniversalTime().AddSeconds(-60);
            DateTime to   = eventTime.ToUniversalTime().AddSeconds(60);

            string filter = $"fields/EventTime ge '{from:yyyy-MM-ddTHH:mm:ssZ}' and " +
                            $"fields/EventTime le '{to:yyyy-MM-ddTHH:mm:ssZ}'";

            string checkUrl = $"https://graph.microsoft.com/v1.0/sites/{_siteId}/lists/{_listId}/items" +
                $"?$expand=fields&$filter={Uri.EscapeDataString(filter)}&$top=20";

            var request = new HttpRequestMessage(HttpMethod.Get, checkUrl);
            request.Headers.Add("Prefer", "HonorNonIndexedQueriesWarningMayFailRandomly");
            var checkResponse = await client.SendAsync(request);
            if (!checkResponse.IsSuccessStatusCode)
                return false;

            var checkObj = JsonConvert.DeserializeObject<JObject>(
                await checkResponse.Content.ReadAsStringAsync());

            var existing = checkObj?["value"] as JArray;
            if (existing == null || existing.Count == 0)
                return false;

            // Cek apakah ada row dengan Title yang sama (ComputerName+EventId+Username)
            // dalam window waktu tersebut.
            foreach (JToken row in existing)
            {
                var fields = row["fields"] as JObject;
                string? existingTitle = fields?["Title"]?.ToString();
                if (string.Equals(existingTitle, title, StringComparison.OrdinalIgnoreCase))
                {
                    SafeWriteEventLog("Application",
                        $"[RAW] Idempotency hit: title='{title}' eventTime={eventTime:O}",
                        EventLogEntryType.Information, 4025);
                    return true;
                }
            }

            return false;
        }

        private static string BuildSummaryKey(string username, string workDate)
            => $"{username}\\{workDate}";

        private static string EscapeODataLiteral(string value)
            => value.Replace("'", "''");

        private static DateTime? ParseFieldDateTime(JObject? fields, string fieldName)
        {
            string? value = fields?[fieldName]?.ToString();
            if (string.IsNullOrWhiteSpace(value)) return null;
            if (!DateTime.TryParse(value, null, System.Globalization.DateTimeStyles.RoundtripKind, out DateTime parsed))
                return null;
            // SharePoint returns UTC (Z suffix) — keep as UTC for consistent comparison
            // with eventTime which is also now always UTC throughout the codebase.
            return parsed.Kind == DateTimeKind.Utc ? parsed : parsed.ToUniversalTime();
        }

        private static string BuildShutdownType(int eventId, string eventType)
            => $"{eventId} - {eventType}";

        private static bool IsShutdownEventId(int eventId)
            => eventId == 1074 || eventId == 6006 || eventId == 4647 ||
               eventId == 6008 || eventId == 41 || eventId == 42;

        /// <summary>
        /// Determines whether this shutdown event qualifies to be written into the Summary.
        ///
        /// Rules:
        ///   • 1074 Restart → never written to Summary (not a real end-of-day).
        ///   • Selain restart, shutdown event selalu dianggap valid (tanpa validasi waktu).
        /// </summary>
        private static bool IsValidShutdownCandidate(
            int eventId, string eventType,
            DateTime shutdownTime,
            DateTime? loginTime, DateTime? expectedTimeOut)
        {
            // 1074 Restart bukan final shutdown — skip
            if (eventId == 1074 && IsRestartEventType(eventType))
                return false;

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
                return IsUnconfirmed6006(eventType) ? 0 : 5;  // unconfirmed = restart = skip

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
