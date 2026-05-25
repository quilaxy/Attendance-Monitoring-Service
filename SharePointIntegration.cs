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

                    // Deteksi error code Azure AD yang spesifik dari response body.
                    // AADSTS7000215 / AADSTS7000222 = ClientSecret invalid atau expired.
                    // AADSTS700016                  = Application (ClientId) tidak ditemukan di tenant.
                    // AADSTS7000215 muncul kalau secret salah; AADSTS7000222 kalau sudah expired.
                    // Keduanya tidak perlu di-retry — retry tidak akan membantu, langsung log Error.
                    bool isSecretExpiredOrInvalid =
                        errorBody.Contains("AADSTS7000215", StringComparison.OrdinalIgnoreCase) ||
                        errorBody.Contains("AADSTS7000222", StringComparison.OrdinalIgnoreCase);
                    bool isAppNotFound =
                        errorBody.Contains("AADSTS700016", StringComparison.OrdinalIgnoreCase);

                    if (isSecretExpiredOrInvalid)
                    {
                        SafeWriteEventLog("Application",
                            $"[TOKEN] CRITICAL: ClientSecret expired atau tidak valid. " +
                            $"Perlu direnew di Azure AD → App registrations → Certificates & secrets, " +
                            $"lalu update ClientSecret di appsettings.json. " +
                            $"AzureError={ExtractAadErrorCode(errorBody)}",
                            EventLogEntryType.Error, 4015);
                        // Tidak perlu retry — secret expired tidak akan tiba-tiba valid lagi.
                        throw new Exception(
                            $"ClientSecret expired atau tidak valid (AADSTS). Dispatch dihentikan sampai secret diperbarui.");
                    }

                    if (isAppNotFound)
                    {
                        SafeWriteEventLog("Application",
                            $"[TOKEN] CRITICAL: ClientId tidak ditemukan di tenant. " +
                            $"Periksa AzureSettings:ClientId dan AzureSettings:TenantId di appsettings.json. " +
                            $"AzureError={ExtractAadErrorCode(errorBody)}",
                            EventLogEntryType.Error, 4016);
                        throw new Exception(
                            $"ClientId tidak ditemukan di tenant Azure AD. Periksa konfigurasi.");
                    }

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

                // Fix 3: tambah filter EventTime ge 30 hari lalu agar tidak return username
                // dari bulan lalu kalau user sudah lama tidak login di device itu.
                DateTime windowStart = referenceTime.AddDays(-30).ToUniversalTime();
                string windowStartStr = windowStart.ToString("yyyy-MM-ddTHH:mm:ssZ");
                string filter = $"fields/ComputerName eq '{EscapeODataLiteral(computerName)}'" +
                                $" and fields/EventTime ge '{windowStartStr}'";
                string url = $"https://graph.microsoft.com/v1.0/sites/{_siteId}/lists/{_listId}/items" +
                             $"?$expand=fields&$filter={Uri.EscapeDataString(filter)}&$top=50&$orderby=fields/EventTime desc";

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
                        Username  = x["fields"]?["Username"]?.ToString(),
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
                    // EventTime  : UTC ISO 8601 — dipakai untuk filter/sort/cleanup (Date Only di SharePoint).
                    // Time       : string HH:mm:ss local — kolom Single Line of Text, untuk tampilan jam.
                    //              Konsisten dengan ClockIn/ClockOut di Summary list.
                    string timeStr = eventTime.ToLocalTime().ToString("HH:mm:ss");

                    var postData = new
                    {
                        fields = new
                        {
                            Title        = title,
                            Username     = username,
                            EventID      = eventId,
                            EventTime    = eventTimeStr,
                            Time         = timeStr,
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

            // ── Cache check ───────────────────────────────────────────────────────
            // Cache membuktikan row sudah ada di SharePoint, tapi TIDAK membuktikan
            // bahwa loginTime yang tersimpan sudah paling awal.
            // Skenario multi-device: Device A login 09:01 (cache terisi), lalu Device B
            // login 07:24 → tanpa pengecekan ini, cache hit langsung return dan ClockIn
            // tidak pernah di-update ke 07:24.
            //
            // Strategi:
            //   • Cache hit + loginTime TIDAK lebih awal → skip (perilaku normal, hemat query).
            //   • Cache hit + loginTime lebih awal        → fall through ke block update.
            //   • Cache miss                              → fall through ke FindSummaryItem (perilaku lama).
            bool cacheHit = summaryCache != null && await summaryCache.ContainsAsync(summaryKey);

            using var client = CreateGraphClient(accessToken, 60);

            if (cacheHit)
            {
                // Query sekali untuk tahu storedLoginTime — hanya dilakukan kalau cache hit.
                var cacheCheckItems = await FindSummaryItemWithRetryAsync(client, summaryKey);
                if (cacheCheckItems != null && cacheCheckItems.Count > 0)
                {
                    var ccFields = cacheCheckItems[0]["fields"] as JObject;
                    DateTime? storedLoginCheck = ParseFieldDateTime(ccFields, "LoginTime");

                    if (storedLoginCheck.HasValue && loginTime >= storedLoginCheck.Value)
                    {
                        // loginTime tidak lebih awal → tidak ada yang perlu di-update.
                        SafeWriteEventLog("Application",
                            $"[DBG-Summary] UpsertLogin: cache hit, loginTime tidak lebih awal " +
                            $"(stored={storedLoginCheck.Value:O} incoming={loginTime:O}) — skipping",
                            EventLogEntryType.Information, 3007);
                        return;
                    }

                    // loginTime lebih awal → fall through ke existingItems block untuk patch.
                    SafeWriteEventLog("Application",
                        $"[DBG-Summary] UpsertLogin: cache hit tapi loginTime lebih awal " +
                        $"(stored={storedLoginCheck?.ToString("O") ?? "(null)"} incoming={loginTime:O}) — patching",
                        EventLogEntryType.Information, 3008);
                }
                // Kalau cacheCheckItems kosong: cache stale (row terhapus di SharePoint).
                // Fall through ke existingItems block untuk create ulang.
            }

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

                // Update ke loginTime yang lebih awal kalau perlu,
                // sekaligus update LoginDevice kalau belum terisi.
                string? storedLoginDevice = fields?["LoginDevice"]?.ToString();
                bool needsEarlierLogin = storedLogin.HasValue && loginTime < storedLogin.Value && !string.IsNullOrWhiteSpace(itemId);
                bool needsLoginDevice  = string.IsNullOrWhiteSpace(storedLoginDevice) && !string.IsNullOrWhiteSpace(itemId);

                if (needsEarlierLogin || needsLoginDevice)
                {
                    SafeWriteEventLog("Application",
                        $"[DBG-Summary] UpsertLogin: patching — earlierLogin={needsEarlierLogin} loginDevice={needsLoginDevice} " +
                        $"loginTime={loginTime:O} device={computerName}",
                        EventLogEntryType.Information, 3003);

                    var loginPatch = new JObject();
                    if (needsEarlierLogin)
                    {
                        loginPatch["LoginTime"]        = ToUtcString(loginTime);
                        loginPatch["ExpectedTimeOut"]  = ToUtcString(loginTime.AddHours(9));
                        loginPatch["ClockIn"]          = ToLocalTimeString(loginTime);
                        loginPatch["ExpectedClockOut"] = ToLocalTimeString(loginTime.AddHours(9));
                        loginPatch["LoginDevice"]      = computerName;
                    }
                    else if (needsLoginDevice)
                    {
                        loginPatch["LoginDevice"] = computerName;
                    }

                    var patchContent = new StringContent(
                        loginPatch.ToString(Newtonsoft.Json.Formatting.None), Encoding.UTF8, "application/json");
                    using var patchRequest = new HttpRequestMessage(new HttpMethod("PATCH"),
                        $"https://graph.microsoft.com/v1.0/sites/{_siteId}/lists/{_summaryListId}/items/{itemId}/fields")
                    { Content = patchContent };
                    var patchResponse = await client.SendAsync(patchRequest);
                    if (!patchResponse.IsSuccessStatusCode)
                    {
                        string body = await patchResponse.Content.ReadAsStringAsync();
                        throw new InvalidOperationException(
                            $"Failed to update LoginTime/LoginDevice for summary key '{summaryKey}' (item {itemId}). Status={patchResponse.StatusCode} Body={body}");
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
                ["Title"]            = summaryKey,
                ["Username"]         = username,
                ["WorkDate"]         = workDate,
                ["LoginTime"]        = ToUtcString(loginTime),
                ["ExpectedTimeOut"]  = ToUtcString(expectedTimeOut),
                ["ClockIn"]          = ToLocalTimeString(loginTime),
                ["ExpectedClockOut"] = ToLocalTimeString(expectedTimeOut),
                ["LoginDevice"]      = computerName,
                ["ClockOut"]         = null,
                ["ShutdownType"]     = string.Empty
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

        /// <summary>
        /// Buat summary row minimal — hanya Title, Username, WorkDate.
        /// Dipakai sebagai fallback saat 4624 tidak ter-capture (Security log overwrite).
        /// Semua kolom lain (LoginTime, LoginDevice, dll) sengaja kosong.
        /// ShutdownTime akan diisi oleh caller setelah row ini terbuat.
        /// Yang penting: row dengan Title+WorkDate sudah ada sehingga ShutdownTime tidak terlewat.
        /// </summary>
        private async Task CreateEmptySummaryRowAsync(
            HttpClient client, string username,
            DateTime shutdownTime, SummaryCache? summaryCache = null)
        {
            string workDate   = shutdownTime.ToLocalTime().ToString("yyyy-MM-dd");
            string summaryKey = BuildSummaryKey(username, workDate);

            var fieldsData = new JObject
            {
                ["Title"]    = summaryKey,
                ["Username"] = username,
                ["WorkDate"] = workDate
            };

            var postData = new JObject { ["fields"] = fieldsData };
            var content  = new StringContent(JsonConvert.SerializeObject(postData), Encoding.UTF8, "application/json");

            var response = await client.PostAsync(
                $"https://graph.microsoft.com/v1.0/sites/{_siteId}/lists/{_summaryListId}/items",
                content);

            if (!response.IsSuccessStatusCode)
            {
                string body = await response.Content.ReadAsStringAsync();
                throw new InvalidOperationException(
                    $"Failed to create empty summary row for key '{summaryKey}'. Status={response.StatusCode} Body={body}");
            }

            SafeWriteEventLog("Application",
                $"[DBG-Summary] CreateEmptySummaryRow: created minimal row summaryKey={summaryKey}",
                EventLogEntryType.Warning, 3028);

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
        ///   • Priority (higher wins): 4647 > 6006-confirmed > 1074-Shutdown > 6008/41.
        ///     4647 adalah priority tertinggi — reliable di semua skenario (sleep, fast startup, hibernate).
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
            IReadOnlyDictionary<string, List<DateTime>> allLogon4624Index,
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
                // Fix B: row tidak ditemukan — kemungkinan 4624 tidak ter-capture karena Security log
                // overwrite sebelum service sempat replay. Daripada skip dan ShutdownTime hilang,
                // buat row baru dengan LoginTime = shutdownTime sebagai estimasi (data minimal),
                // lalu lanjutkan untuk tulis ShutdownTime ke row yang baru dibuat.
                // Username sudah diketahui dari 4647 — tidak perlu resolve dari event baru.
                SafeWriteEventLog("Application",
                    $"[DBG-Summary] TryUpdateShutdown: no summary row found for user={username} " +
                    $"computer={computerName} shutdownTime={shutdownTime:O}. " +
                    $"Creating estimated row — login event likely missed due to Security log overwrite.",
                    EventLogEntryType.Warning, 3025);

                try
                {
                    // Buat row minimal — hanya Title, Username, WorkDate.
                    // Semua kolom lain kosong, ShutdownTime diisi setelah row terbuat.
                    await CreateEmptySummaryRowAsync(client, username, shutdownTime, summaryCache);

                    // Fetch row yang baru dibuat untuk lanjutkan update ShutdownTime
                    summaryItem = await FindSummaryItemForShutdownAsync(client, computerName, username, shutdownTime, summaryCache);
                }
                catch (Exception ex)
                {
                    SafeWriteEventLog("Application",
                        $"[DBG-Summary] TryUpdateShutdown: failed to create estimated row for user={username}: {ex.Message}",
                        EventLogEntryType.Warning, 3026);
                }

                if (summaryItem == null)
                {
                    SafeWriteEventLog("Application",
                        $"[DBG-Summary] TryUpdateShutdown: SKIP — could not create or find summary row for user={username}",
                        EventLogEntryType.Warning, 3027);
                    return;
                }
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
            // Kalau belum ada ShutdownTime sama sekali, set sentinel priority -2 agar
            // semua event shutdown valid (priority >= -1) bisa masuk.
            // Event 42 (priority -1) tetap bisa masuk kalau currentShutdown null,
            // tapi akan di-overwrite oleh event yang lebih baik (priority >= 0) kapanpun datang.
            // Ini berbeda dari noExistingShutdown=true yang skip priority check sepenuhnya —
            // di sini priority check tetap jalan, hanya baseline-nya di-set ke -2 bukan 0.
            int effectiveCurrentPriority = currentShutdown.HasValue ? currentPriority : -2;

            // isNewSession: sesi baru = ada 4624 login setelah currentShutdown.
            // Definisi ini paling akurat — tidak bergantung threshold waktu atau exclude event ID.
            // Pakai allLogon4624Index (in-memory, semua login per computer per hari) untuk
            // cek apakah ada login baru setelah shutdown terakhir tanpa perlu query ke mana-mana.
            // Berbeda dari firstLogon4624Index yang hanya simpan earliest, allLogon4624Index
            // simpan semua login — penting untuk kasus multiple login/logout dalam sehari.
            //
            // Contoh 1x login logout:
            //   4647 17:00 tersimpan → 1074/6006/42 datang tanpa ada 4624 baru
            //   → isNewSession = false → priority check ketat → 4647 tidak bisa dioverride ✅
            //
            // Contoh multiple login logout:
            //   4647 12:00 tersimpan → 4624 13:00 login lagi → 4647 17:00
            //   → isNewSession = true (ada 4624 jam 13:00 setelah 12:00) ✅
            bool isNewSession = false;
            if (currentShutdown.HasValue && shutdownTime > currentShutdown.Value)
            {
                string workDate = shutdownTime.ToLocalTime().ToString("yyyy-MM-dd");
                // KEY HARUS SAMA dengan BuildDeviceWorkDateKey di LoginLogoutMonitorService:
                // $"{computerName}::{workDate}" — bukan underscore.
                // Bug sebelumnya: pakai "_" sehingga TryGetValue tidak pernah match
                // dan isNewSession selalu false untuk semua skenario multiple login/logout.
                string indexKey = $"{computerName}::{workDate}";
                if (allLogon4624Index.TryGetValue(indexKey, out var logins))
                {
                    isNewSession = logins.Any(t =>
                        t > currentShutdown.Value &&
                        t <= shutdownTime);
                }
            }
            if (isNewSession)
            {
                SafeWriteEventLog("Application",
                    $"[DBG-Summary] TryUpdateShutdown: NEW SESSION detected — " +
                    $"incoming shutdownTime ({shutdownTime:O}) > existing ({currentShutdown!.Value:O}). " +
                    $"Resetting priority comparison. new={newPriority} old={effectiveCurrentPriority}",
                    EventLogEntryType.Information, 3018);
                // Sesi baru → tulis langsung tanpa cek priority lama.
            }
            else
            {
                // Sesi yang sama — terapkan priority system normal dengan effectiveCurrentPriority.
                if (newPriority < effectiveCurrentPriority)
                {
                    SafeWriteEventLog("Application",
                        $"[DBG-Summary] TryUpdateShutdown: SKIP — priority too low: " +
                        $"new={newPriority} effectiveCurrent={effectiveCurrentPriority} " +
                        $"(existing='{currentShutdownType}' currentShutdown={currentShutdown?.ToString("O") ?? "null"})",
                        EventLogEntryType.Information, 3014);
                    return;
                }

                if (newPriority == effectiveCurrentPriority)
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
                ["ClockOut"]     = ToLocalTimeString(shutdownTime),
                ["ShutdownType"] = shutdownTypeStr,
                ["LogoutDevice"] = computerName   // device yang shutdown, bisa beda dengan LoginDevice
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

            // Filter server-side: hanya fetch item yang dateField < cutoffDate.
            // Jauh lebih efisien dari fetch-all lalu filter di client — SharePoint yang filter,
            // bukan kita yang scan semua 23.000+ item hanya untuk hapus beberapa ratus.
            // Format cutoffDate sebagai ISO 8601 UTC agar OData filter konsisten
            // dengan format yang disimpan SharePoint (EventTime = UTC, WorkDate = date string).
            string cutoffStr = cutoffDate.ToString("yyyy-MM-dd");
            string filter = $"fields/{dateField} lt '{cutoffStr}'";

            string? url = $"https://graph.microsoft.com/v1.0/sites/{_siteId}/lists/{listId}/items" +
                          $"?$expand=fields&$select=id,fields" +
                          $"&$filter={Uri.EscapeDataString(filter)}" +
                          $"&$top=500"; // lebih kecil dari sebelumnya — kita hanya fetch yang akan dihapus

            while (!string.IsNullOrWhiteSpace(url))
            {
                var response = await GetWithThrottleRetryAsync(client, url);
                if (!response.IsSuccessStatusCode)
                {
                    SafeWriteEventLog("Application",
                        $"[CLEANUP] Page fetch failed for listId='{listId}' — " +
                        $"HTTP {(int)response.StatusCode}. Stopping pagination, " +
                        $"{deletedCount} items deleted so far.",
                        EventLogEntryType.Warning, 5004);
                    break;
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
                            // Server sudah filter dateField < cutoffDate — semua item di sini
                            // memang perlu dihapus. Tidak perlu filter ulang di sisi client.
                            string? itemId = item["id"]?.ToString();
                            if (string.IsNullOrWhiteSpace(itemId))
                                continue;

                            var deleteResponse = await DeleteWithThrottleRetryAsync(
                                client,
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

        private static async Task<HttpResponseMessage> GetWithThrottleRetryAsync(
            HttpClient client, string url, int maxRetries = 3)
        {
            for (int attempt = 1; attempt <= maxRetries; attempt++)
            {
                var response = await client.GetAsync(url);

                if ((int)response.StatusCode == 429)
                {
                    int retryAfterSeconds = 30 * attempt;
                    if (response.Headers.TryGetValues("Retry-After", out var values) &&
                        int.TryParse(values.FirstOrDefault(), out int headerSeconds))
                    {
                        retryAfterSeconds = Math.Min(headerSeconds, 120);
                    }

                    SafeWriteEventLog("Application",
                        $"[CLEANUP] SharePoint throttle (429) — waiting {retryAfterSeconds}s before retry " +
                        $"(attempt {attempt}/{maxRetries}).",
                        EventLogEntryType.Warning, 5007);

                    await Task.Delay(TimeSpan.FromSeconds(retryAfterSeconds));
                    continue;
                }

                return response;
            }

            return await client.GetAsync(url);
        }

        private static async Task<HttpResponseMessage> DeleteWithThrottleRetryAsync(
            HttpClient client, string url, int maxRetries = 3)
        {
            for (int attempt = 1; attempt <= maxRetries; attempt++)
            {
                var response = await client.DeleteAsync(url);

                if ((int)response.StatusCode == 429)
                {
                    int retryAfterSeconds = 30 * attempt;
                    if (response.Headers.TryGetValues("Retry-After", out var values) &&
                        int.TryParse(values.FirstOrDefault(), out int headerSeconds))
                    {
                        retryAfterSeconds = Math.Min(headerSeconds, 120);
                    }

                    SafeWriteEventLog("Application",
                        $"[CLEANUP] Delete throttled (429) — waiting {retryAfterSeconds}s " +
                        $"(attempt {attempt}/{maxRetries}).",
                        EventLogEntryType.Warning, 5007);

                    await Task.Delay(TimeSpan.FromSeconds(retryAfterSeconds));
                    continue;
                }

                return response;
            }

            return await client.DeleteAsync(url);
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
            if (!LoginLogoutMonitorService.VerboseLogging && _verboseOnlyEventIds.Contains(eventId))
                return;

            try
            {
                EventLog.WriteEntry("Attendance-Service", message, type, eventId);
            }
            catch { }
        }

        /// <summary>
        /// Event ID yang hanya ditulis saat VerboseLogging=true.
        /// </summary>
        private static readonly HashSet<int> _verboseOnlyEventIds = new HashSet<int>
        {
            // SharePoint summary detail
            3001, 3002, 3003, 3004, 3005, 3007, 3008,
            3010, 3011, 3012, 3013, 3014, 3015, 3016, 3017, 3018, 3019, 3021, 3022, 3023,
            // Dispatch & raw detail
            4010, 4011, 4020, 4021, 4022, 4025,
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

        /// <summary>
        /// Ekstrak error code Azure AD (format "AADSTS######") dari response body token endpoint.
        /// Dipakai untuk log pesan error yang actionable tanpa dump seluruh response body.
        /// Kalau tidak ditemukan, return "(unknown)".
        /// </summary>
        private static string ExtractAadErrorCode(string responseBody)
        {
            try
            {
                // Response body adalah JSON: {"error":"invalid_client","error_description":"AADSTS7000222: ..."}
                // Cukup cari pola AADSTS diikuti angka tanpa perlu full JSON parse.
                var match = System.Text.RegularExpressions.Regex.Match(
                    responseBody, @"AADSTS\d+", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                return match.Success ? match.Value : "(unknown)";
            }
            catch { return "(unknown)"; }
        }

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

            // Event 42 (Sleep) hanya boleh masuk kalau sudah lolos ShouldUseEvent42AsLastResortAsync.
            // Di sini selalu dianggap valid — guard sudah dilakukan di sisi service sebelum dispatch.
            return true;
        }

        /// <summary>
        /// Priority for Summary ShutdownTime. Higher value wins.
        ///   4647 User Logout        = 6  (HIGHEST — explicit logoff dari Security log, reliable di semua skenario
        ///                                  termasuk sleep/hibernate/fast-startup yang tidak punya 1074 atau 6006)
        ///   6006 confirmed shutdown = 5  (paired 1074 was power-off/shutdown)
        ///   1074 Shutdown           = 4  (confirmed power-off, no 6006 yet)
        ///   6006 unconfirmed        = 0  (no paired 1074 — kemungkinan restart, di-skip)
        ///   6008 Unexpected         = 1
        ///   41   Crash              = 1
        ///   42   Sleep last-resort  = -1 (hanya kalau tidak ada event lain sama sekali)
        /// </summary>
        private static int GetShutdownPriority(int eventId, string eventType)
        {
            if (eventId == 4647) return 6; // Priority tertinggi — explicit user logoff dari Security log
            if (eventId == 1074 && !IsRestartEventType(eventType)) return 5; // was 4 — FIX B: 1074 > 6006 confirmed
            if (eventId == 6006)
                return IsUnconfirmed6006(eventType) ? 0 : 4;  // was 5 — FIX B: 6006 confirmed turun ke 4
            if (eventId == 6008) return 1;
            if (eventId == 41)   return 1;
            // Event 42 last-resort: priority -1 sehingga ANY event lain selalu overwrite.
            // isNewSession check di TryUpdateDailySummaryShutdownAsync tetap berlaku —
            // 42 dari sesi yang lebih baru tetap overwrite shutdown lama.
            if (eventId == 42)   return -1;
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