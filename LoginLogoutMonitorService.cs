using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;

namespace EventLogOutEmployeeService
{
    public class LoginLogoutMonitorService : ServiceBase
    {
        private EventLog? securityEventLog;
        private EventLog? systemEventLog;
        private string lastActiveUser = string.Empty;
        private CancellationTokenSource? cancellationTokenSource;
        private CancellationToken? cancellationToken;
        private readonly object userLock = new object();
        private int activeDispatchCount = 0;
        private DateTime serviceStartTime;
        private readonly Lazy<SharePointIntegration> sharePointIntegration =
            new Lazy<SharePointIntegration>(() => new SharePointIntegration());

        // Shared 1074 state for resolving adjacent 6006 events.
        private static readonly object last1074Lock = new object();
        private static string? last1074Username;
        private static DateTime last1074EventTime = DateTime.MinValue;
        private static string? last1074ShutdownType;

        private static readonly string DataDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Attendance-Monitoring-Service");

        private readonly string stopCheckpointPath =
            Path.Combine(DataDirectory, "event-stop.checkpoint");

        private readonly string replayCheckpointPath =
            Path.Combine(DataDirectory, "event-replay.checkpoint");

        private readonly PersistentEventQueue eventQueue =
            new PersistentEventQueue(Path.Combine(DataDirectory, "event-queue.json"));

        public LoginLogoutMonitorService()
        {
            try
            {
                if (Environment.OSVersion.Platform == PlatformID.Win32NT)
                {
                    int retryCount = 3;
                    Exception? lastException = null;

                    for (int i = 0; i < retryCount; i++)
                    {
                        try
                        {
                            securityEventLog = new EventLog("Security");
                            systemEventLog = new EventLog("System");

                            if (securityEventLog != null)
                                securityEventLog.EntryWritten += new EntryWrittenEventHandler(OnSecurityEventWritten);

                            if (systemEventLog != null)
                                systemEventLog.EntryWritten += new EntryWrittenEventHandler(OnSystemEventWritten);

                            break;
                        }
                        catch (Exception ex)
                        {
                            lastException = ex;
                            if (i < retryCount - 1)
                                Thread.Sleep(2000);
                        }
                    }

                    if (lastException != null && securityEventLog == null)
                        throw lastException;
                }
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("Application",
                    $"EmployeeLoginLogoutService constructor error: {ex.Message}",
                    EventLogEntryType.Error, 1001);
                throw;
            }
        }

        public void StartForConsole(string[] args) => OnStart(args);
        public void StopForConsole() => OnStop();

        protected override void OnStart(string[] args)
        {
            int maxRetries = 5;
            int currentRetry = 0;
            bool started = false;

            while (currentRetry < maxRetries)
            {
                try
                {
                    currentRetry++;

                    serviceStartTime = DateTime.Now;

                    // Reset static network-wait flag so it re-evaluates on each service start
                    SharePointIntegration.ResetNetworkWaitFlag();
                    SharePointIntegration.SetServiceStartTime(serviceStartTime);

                    int delaySeconds = (currentRetry == 1) ? 10 : 3;
                    Thread.Sleep(delaySeconds * 1000);

                    string publishDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "");
                    Directory.SetCurrentDirectory(publishDirectory);

                    _ = LoadConfiguration(publishDirectory);

                    cancellationTokenSource = new CancellationTokenSource();
                    cancellationToken = cancellationTokenSource.Token;

                    // Replay any events missed while service was down
                    ReplayMissedEventsFromCheckpoint();

                    Thread monitoringThread = new Thread(() => MonitorEvents(cancellationToken.Value));
                    monitoringThread.IsBackground = true;
                    monitoringThread.Start();

                    started = true;
                    break;
                }
                catch (Exception ex)
                {
                    if (currentRetry >= maxRetries)
                    {
                        EventLog.WriteEntry("Application",
                            $"EmployeeLoginLogoutService failed to start after {maxRetries} attempts: {ex.Message}",
                            EventLogEntryType.Error, 1002);
                        return;
                    }
                    Thread.Sleep(2000);
                }
            }

            if (started)
            {
                EventLog.WriteEntry("Attendance-Service",
                    "Service started successfully.",
                    EventLogEntryType.Information, 0);
            }
        }

        // ─── Replay missed events ────────────────────────────────────────────────

        private void ReplayMissedEventsFromCheckpoint()
        {
            try
            {
                DateTime replayTo = DateTime.Now;
                DateTime? replayFrom = LoadStopCheckpoint();

                if (replayFrom.HasValue)
                {
                    ReplaySecurityEvents(replayFrom, replayTo);
                    ReplaySystemEvents(replayFrom, replayTo);
                }

                SaveReplayCheckpoint(replayTo);
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("Application",
                    $"Error while replaying startup events: {ex.Message}",
                    EventLogEntryType.Warning, 1014);
            }
        }

        private DateTime? LoadStopCheckpoint()
        {
            try
            {
                if (!File.Exists(stopCheckpointPath))
                    return null;

                string value = File.ReadAllText(stopCheckpointPath).Trim();
                if (DateTime.TryParse(value, null,
                        System.Globalization.DateTimeStyles.RoundtripKind, out DateTime parsed))
                    return parsed.ToLocalTime();
            }
            catch { /* ignore malformed checkpoint */ }

            return null;
        }

        private void SaveStopCheckpoint(DateTime checkpoint)
        {
            try
            {
                string? dir = Path.GetDirectoryName(stopCheckpointPath);
                if (!string.IsNullOrWhiteSpace(dir) && !Directory.Exists(dir))
                    Directory.CreateDirectory(dir);

                File.WriteAllText(stopCheckpointPath,
                    checkpoint.ToUniversalTime().ToString("O"));
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("Application",
                    $"Failed to save stop checkpoint: {ex.Message}",
                    EventLogEntryType.Warning, 1017);
            }
        }

        private void SaveReplayCheckpoint(DateTime checkpoint)
        {
            try
            {
                File.WriteAllText(replayCheckpointPath,
                    checkpoint.ToUniversalTime().ToString("O"));
            }
            catch { /* ignore write failures */ }
        }

        private void ReplaySecurityEvents(DateTime? fromTime, DateTime toTime)
        {
            if (securityEventLog == null)
                return;

            // Walk backwards; skip entries outside [fromTime, toTime] (timestamps may be out-of-order).
            for (int i = securityEventLog.Entries.Count - 1; i >= 0; i--)
            {
                EventLogEntry entry = securityEventLog.Entries[i];
                DateTime eventTime = entry.TimeGenerated;

                if (fromTime.HasValue && eventTime <= fromTime.Value)
                    continue;

                if (eventTime > toTime)
                    continue;

                int eventId = unchecked((int)entry.InstanceId);
                if (eventId != 4624 && eventId != 4647)
                    continue;

                ProcessSecurityEntryAsync(entry, writeRawRecord: true).GetAwaiter().GetResult();
            }
        }

        private void ReplaySystemEvents(DateTime? fromTime, DateTime toTime)
        {
            if (systemEventLog == null)
                return;

            for (int i = systemEventLog.Entries.Count - 1; i >= 0; i--)
            {
                EventLogEntry entry = systemEventLog.Entries[i];
                DateTime eventTime = entry.TimeGenerated;

                if (fromTime.HasValue && eventTime <= fromTime.Value)
                    continue;

                if (eventTime > toTime)
                    continue;

                int eventId = unchecked((int)entry.InstanceId);
                if (eventId != 1074 && eventId != 6006 && eventId != 6008 && eventId != 41 && eventId != 42)
                    continue;

                ProcessSystemEntryAsync(entry, writeRawRecord: true).GetAwaiter().GetResult();
            }
        }

        // ─── Configuration ───────────────────────────────────────────────────────

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

            try
            {
                byte[] encryptedData = File.ReadAllBytes(encryptedConfigPath);
                byte[] decryptedData = ProtectedData.Unprotect(encryptedData, null, DataProtectionScope.LocalMachine);
                string jsonContent = Encoding.UTF8.GetString(decryptedData);

                var configBuilder = new ConfigurationBuilder();
                using var stream = new MemoryStream(Encoding.UTF8.GetBytes(jsonContent));
                configBuilder.AddJsonStream(stream);
                return configBuilder.Build();
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("Application",
                    $"Failed to decrypt configuration: {ex.Message}",
                    EventLogEntryType.Error, 1004);
                throw;
            }
        }

        // ─── Lifecycle ───────────────────────────────────────────────────────────

        protected override void OnStop()
        {
            try
            {
                // Save checkpoint first with a safety buffer to guarantee replay coverage
                // for events written right around shutdown/startup transitions.
                DateTime stopCheckpoint = DateTime.Now.AddMinutes(-5);

                EventLog.WriteEntry("Application",
                    $"OnStop: saving checkpoint {stopCheckpoint:O} to {stopCheckpointPath}",
                    EventLogEntryType.Information, 1018);

                SaveStopCheckpoint(stopCheckpoint);

                EventLog.WriteEntry("Application",
                    $"OnStop: checkpoint saved, FileExists={File.Exists(stopCheckpointPath)}",
                    EventLogEntryType.Information, 1019);

                if (securityEventLog != null)
                {
                    securityEventLog.EnableRaisingEvents = false;
                    securityEventLog.EntryWritten -= OnSecurityEventWritten;
                }

                if (systemEventLog != null)
                {
                    systemEventLog.EnableRaisingEvents = false;
                    systemEventLog.EntryWritten -= OnSystemEventWritten;
                }

                cancellationTokenSource?.Cancel();

                // Wait up to 15 seconds for the queue worker to finish its current HTTP call
                // so we don't lose an in-flight dispatch on restart
                int waited = 0;
                while (waited < 15000)
                {
                    int count = eventQueue.GetCountAsync().GetAwaiter().GetResult();
                    int processing = Volatile.Read(ref activeDispatchCount);
                    if (count == 0 && processing == 0) break;
                    Thread.Sleep(500);
                    waited += 500;
                }

                EventLog.WriteEntry("Attendance-Service",
                    "Service has been successfully shut down.",
                    EventLogEntryType.Information, 0);
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("Application",
                    $"Error in OnStop: {ex.Message}",
                    EventLogEntryType.Warning, 1006);
            }
        }

        // ─── Monitor loop ────────────────────────────────────────────────────────

        private void MonitorEvents(CancellationToken cancellationToken)
        {
            try
            {
                if (securityEventLog != null)
                    securityEventLog.EnableRaisingEvents = true;

                if (systemEventLog != null)
                    systemEventLog.EnableRaisingEvents = true;

                Task.Run(() => CleanupOldRecordsTask(cancellationToken), cancellationToken);
                Task.Run(() => ProcessQueuedEventsTask(cancellationToken), cancellationToken);

                while (!cancellationToken.IsCancellationRequested)
                    Thread.Sleep(5000);
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("Application",
                    $"Error in MonitorEvents: {ex.Message}",
                    EventLogEntryType.Error, 1007);
            }
        }

        // ─── Queue processor ─────────────────────────────────────────────────────

        private async Task ProcessQueuedEventsTask(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    QueuedAttendanceEvent? next = await eventQueue.PeekAsync(cancellationToken);
                    if (next == null)
                    {
                        await Task.Delay(TimeSpan.FromSeconds(5), cancellationToken);
                        continue;
                    }

                    Interlocked.Increment(ref activeDispatchCount);
                    bool sent;
                    try
                    {
                        sent = await TryDispatchQueuedEventAsync(next);
                    }
                    finally
                    {
                        Interlocked.Decrement(ref activeDispatchCount);
                    }

                    if (sent)
                    {
                        await eventQueue.RemoveByIdAsync(next.QueueId, cancellationToken);
                        continue;
                    }

                    await Task.Delay(TimeSpan.FromSeconds(10), cancellationToken);
                }
                catch (TaskCanceledException) { break; }
                catch (Exception ex)
                {
                    EventLog.WriteEntry("Application",
                        $"Error in ProcessQueuedEventsTask: {ex.Message}",
                        EventLogEntryType.Warning, 1015);
                    try { await Task.Delay(TimeSpan.FromSeconds(15), cancellationToken); }
                    catch (TaskCanceledException) { break; }
                }
            }
        }

        private static bool ShouldProcessSummary(QueuedAttendanceEvent item)
        {
            return item.EventId == 4624 || item.EventId == 1074 || item.EventId == 6006 ||
                   item.EventId == 4647 || item.EventId == 6008 || item.EventId == 41;
        }

        private async Task<bool> TryDispatchQueuedEventAsync(QueuedAttendanceEvent item)
        {
            try
            {
                var sharePoint = sharePointIntegration.Value;
                string? accessToken = await sharePoint.GetAccessTokenAsync(item.EventTime, item.EventId);
                if (string.IsNullOrEmpty(accessToken))
                    return false;

                bool needsRaw = item.WriteRawRecord && !item.RawRecordDispatched;
                bool needsSummary = ShouldProcessSummary(item) && !item.SummaryDispatched;

                if (needsRaw)
                {
                    await sharePoint.AddRecordToSharePointAsync(
                        accessToken, item.Username, item.EventTime,
                        item.EventId, item.EventType, item.ComputerName);

                    await eventQueue.UpdateDispatchStateAsync(item.QueueId, rawRecordDispatched: true);
                    item.RawRecordDispatched = true;
                }

                if (needsSummary)
                {
                    if (item.EventId == 4624)
                    {
                        await sharePoint.UpsertDailySummaryLoginAsync(
                            accessToken, item.Username, item.ComputerName,
                            item.LoginTime ?? item.EventTime);
                    }
                    else
                    {
                        await sharePoint.TryUpdateDailySummaryShutdownAsync(
                            accessToken, item.Username, item.ComputerName,
                            item.ShutdownTime ?? item.EventTime,
                            item.EventId, item.EventType);
                    }

                    await eventQueue.UpdateDispatchStateAsync(item.QueueId, summaryDispatched: true);
                    item.SummaryDispatched = true;
                }

                bool doneRaw = !item.WriteRawRecord || item.RawRecordDispatched;
                bool doneSummary = !ShouldProcessSummary(item) || item.SummaryDispatched;
                return doneRaw && doneSummary;
            }
            catch
            {
                return false;
            }
        }

        // ─── Cleanup ─────────────────────────────────────────────────────────────

        private async Task CleanupOldRecordsTask(CancellationToken cancellationToken)
        {
            int cleanupHour = 3;
            int retentionMonths = 6;

            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    DateTime now = DateTime.Now;
                    DateTime nextRun = now.Date.AddHours(cleanupHour);

                    if (now.Hour >= cleanupHour)
                        nextRun = nextRun.AddDays(1);

                    bool missedCleanup = now.Hour > cleanupHour;
                    if (missedCleanup)
                    {
                        int randomDelay = new Random(Environment.MachineName.GetHashCode()).Next(0, 300000);
                        await Task.Delay(randomDelay, cancellationToken);
                        await sharePointIntegration.Value.CleanupOldRecordsAsync(retentionMonths);
                    }

                    await Task.Delay(nextRun - DateTime.Now, cancellationToken);

                    int scheduledDelay = new Random(Environment.MachineName.GetHashCode()).Next(0, 300000);
                    await Task.Delay(scheduledDelay, cancellationToken);
                    await sharePointIntegration.Value.CleanupOldRecordsAsync(retentionMonths);
                }
                catch (TaskCanceledException) { break; }
                catch (Exception ex)
                {
                    EventLog.WriteEntry("Application",
                        $"Error in CleanupOldRecordsTask: {ex.Message}",
                        EventLogEntryType.Warning, 1008);
                    try { await Task.Delay(TimeSpan.FromHours(1), cancellationToken); }
                    catch (TaskCanceledException) { break; }
                }
            }
        }

        // ─── Event handlers ──────────────────────────────────────────────────────

        private async void OnSecurityEventWritten(object sender, EntryWrittenEventArgs e)
        {
            if (e?.Entry == null) return;
            await ProcessSecurityEntryAsync(e.Entry, writeRawRecord: true);
        }

        private async Task ProcessSecurityEntryAsync(EventLogEntry log, bool writeRawRecord)
        {
            try
            {
                int eventId = unchecked((int)log.InstanceId);
                if (eventId != 4624 && eventId != 4647) return;

                DateTime eventTime = log.TimeGenerated;
                string computerName = log.MachineName;
                string eventMessage = log.Message;

                // Parse logon type (only relevant for 4624)
                int logonType = 0;
                if (eventId == 4624)
                    logonType = ParseLogonType(eventMessage);

                if (eventId == 4624 && !IsRelevantLogonType(logonType))
                    return;

                string? username = GetUsernameFromEvent(eventMessage, eventId);
                if (string.IsNullOrEmpty(username) || !IsValidUsername(username))
                    return;

                if (eventId == 4624)
                {
                    lock (userLock)
                        lastActiveUser = username;
                }

                await ProcessEvent(eventId, username, eventTime, computerName,
                    "Security", logonType, null, writeRawRecord);
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("Application",
                    $"Error in ProcessSecurityEntryAsync: {ex.Message}",
                    EventLogEntryType.Warning, 1009);
            }
        }

        private async void OnSystemEventWritten(object sender, EntryWrittenEventArgs e)
        {
            if (e?.Entry == null) return;
            await ProcessSystemEntryAsync(e.Entry, writeRawRecord: true);
        }

        private async Task ProcessSystemEntryAsync(EventLogEntry log, bool writeRawRecord)
        {
            try
            {
                int eventId = unchecked((int)log.InstanceId);
                if (eventId != 1074 && eventId != 6006 && eventId != 6008 && eventId != 41 && eventId != 42)
                    return;

                if (eventId == 1074 && log.Message == null)
                    return;

                DateTime eventTime = log.TimeGenerated;
                string computerName = log.MachineName;

                string? eventMessage = (eventId == 1074) ? log.Message : null;
                string? username = (eventId == 1074) ? GetUserFromSystem1074Message(eventMessage) : null;

                if (eventId == 1074 && !string.IsNullOrEmpty(username))
                {
                    string shutdownType = ParseShutdownType(eventMessage);
                    StoreLast1074State(username, eventTime, shutdownType);
                }

                if (eventId == 6006)
                    username = TryResolveUsernameFor6006(eventTime) ?? username;

                if (string.IsNullOrEmpty(username))
                {
                    lock (userLock)
                        username = lastActiveUser;
                }

                if (string.IsNullOrEmpty(username))
                {
                    username = GetMostRecentUser(eventTime);
                    if (string.IsNullOrEmpty(username))
                        return;
                }

                if (eventId == 42)
                    SharePointIntegration.MarkSleepEvent(eventTime);

                await ProcessEvent(eventId, username, eventTime, computerName,
                    "System", 0, eventMessage, writeRawRecord);
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("Application",
                    $"Error in ProcessSystemEntryAsync: {ex.Message}",
                    EventLogEntryType.Warning, 1010);
            }
        }

        // ─── Core event builder ──────────────────────────────────────────────────

        private async Task ProcessEvent(
            int eventId, string username, DateTime eventTime,
            string computerName, string logType,
            int logonType, string? eventMessage,
            bool writeRawRecord)
        {
            try
            {
                string eventType = logType switch
                {
                    "Security" => eventId switch
                    {
                        4624 => $"User Login\nLogon Type: {FormatLogonType(logonType)}",
                        4647 => "User Logout",
                        _ => "Unknown Security Event"
                    },
                    "System" => eventId switch
                    {
                        1074 => ParseShutdownType(eventMessage),
                        6006 => "Shutdown Completed",
                        6008 => "Unexpected Shutdown",
                        41   => "System Crash",
                        42   => "Sleep",
                        _    => "Unknown System Event"
                    },
                    _ => "Unknown Event"
                };

                if (eventTime.Kind == DateTimeKind.Unspecified)
                    eventTime = DateTime.SpecifyKind(eventTime, DateTimeKind.Local);

                if (eventId == 1074 || eventId == 6006 || eventId == 4647 ||
                    eventId == 6008 || eventId == 41 || eventId == 42)
                    SharePointIntegration.MarkShutdownEvent(eventTime);

                DateTime? loginTime = null;
                DateTime? expectedTimeOut = null;
                DateTime? shutdownTime = null;
                string? shutdownType = null;

                if (eventId == 4624)
                {
                    loginTime = eventTime;
                    expectedTimeOut = eventTime.AddHours(9);
                }
                else if (eventId == 1074 || eventId == 6006 ||
                         eventId == 4647 || eventId == 6008 || eventId == 41)
                {
                    shutdownTime = eventTime;
                    shutdownType = $"{eventId} - {eventType}";
                }

                var queuedEvent = new QueuedAttendanceEvent
                {
                    QueueId       = Guid.NewGuid().ToString("N"),
                    EventId       = eventId,
                    Username      = username,
                    EventTime     = eventTime,
                    ComputerName  = computerName,
                    EventType     = eventType,
                    LogonType     = logonType,
                    LoginTime     = loginTime,
                    ExpectedTimeOut = expectedTimeOut,
                    ShutdownTime  = shutdownTime,
                    ShutdownType  = shutdownType,
                    WriteRawRecord = writeRawRecord
                };

                bool enqueued = await eventQueue.EnqueueIfNotDuplicateAsync(queuedEvent);

                if (!enqueued)
                {
                    EventLog.WriteEntry("Application",
                        $"Duplicate event skipped: EventId={eventId} User={username} Time={eventTime:HH:mm:ss}",
                        EventLogEntryType.Information, 1016);
                }
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("Application",
                    $"Error in ProcessEvent: {ex.Message}",
                    EventLogEntryType.Warning, 1011);
            }
        }

        // ─── Helpers ─────────────────────────────────────────────────────────────

        private string? GetMostRecentUser(DateTime beforeTime)
        {
            try
            {
                DateTime lookbackTime = beforeTime.AddHours(-12);
                EventLog secLog = new EventLog("Security");
                int checkCount = 0;

                for (int i = secLog.Entries.Count - 1; i >= 0 && checkCount < 500; i--)
                {
                    checkCount++;
                    EventLogEntry entry = secLog.Entries[i];

                    if ((unchecked((int)entry.InstanceId) == 4624 ||
                         unchecked((int)entry.InstanceId) == 4647) &&
                        entry.TimeGenerated >= lookbackTime &&
                        entry.TimeGenerated <= beforeTime &&
                        entry.Message != null)
                    {
                        int secEventId = unchecked((int)entry.InstanceId);
                        if (secEventId == 4624)
                        {
                            int lt = ParseLogonType(entry.Message);
                            if (!IsRelevantLogonType(lt))
                                continue;
                        }

                        string? u = GetUsernameFromEvent(entry.Message, secEventId);
                        if (!string.IsNullOrEmpty(u) && IsValidUsername(u))
                            return u;
                    }
                }
            }
            catch { /* silent fail */ }

            return null;
        }

        private int ParseLogonType(string message)
        {
            try
            {
                // "Logon Type:   11"  — appears under "Logon Information:" section
                var match = Regex.Match(message, @"Logon Type:\s*(\d+)");
                if (match.Success && int.TryParse(match.Groups[1].Value, out int lt))
                    return lt;
            }
            catch { /* silent fail */ }
            return 0;
        }

        private string FormatLogonType(int logonType)
        {
            return logonType switch
            {
                2  => "2 - Interactive",
                7  => "7 - Unlock",
                10 => "10 - RemoteInteractive",
                11 => "11 - CachedInteractive",
                _  => $"{logonType} - Other"
            };
        }

        private string ParseShutdownType(string? eventMessage)
        {
            if (string.IsNullOrEmpty(eventMessage))
                return "Shutdown/Restart Initiated";

            try
            {
                var match = Regex.Match(eventMessage, @"Shut-down Type:\s*([^\r\n]+)", RegexOptions.IgnoreCase);
                if (match.Success)
                {
                    string type = match.Groups[1].Value.Trim().ToLower();
                    if (type.Contains("restart") || type.Contains("reboot"))
                        return "Restart Initiated";
                    if (type.Contains("power off") || type.Contains("shutdown"))
                        return "Shutdown Initiated";
                }
            }
            catch { /* silent fail */ }

            return "Shutdown/Restart Initiated";
        }

        private string? GetUsernameFromEvent(string message, int eventId)
        {
            try
            {
                if (eventId == 4624)
                {
                    int newLogonIndex = message.IndexOf("New Logon:");
                    if (newLogonIndex == -1) return null;

                    string section = message.Substring(newLogonIndex);
                    var match = Regex.Match(section, @"Account Name:\s*([^\r\n]+)");
                    if (!match.Success) return null;

                    string accountName = match.Groups[1].Value.Trim();
                    if (string.IsNullOrWhiteSpace(accountName) ||
                        accountName.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase) ||
                        accountName.Equals("-", StringComparison.OrdinalIgnoreCase) ||
                        accountName.EndsWith("$", StringComparison.OrdinalIgnoreCase))
                        return null;

                    return accountName.Contains("@") ? accountName.Split('@')[0].Trim() : accountName;
                }

                if (eventId == 4647)
                {
                    int subjectIndex = message.IndexOf("Subject:");
                    if (subjectIndex == -1) return null;

                    string section = message.Substring(subjectIndex);
                    var match = Regex.Match(section, @"Account Name:\s*([^\r\n]+)");
                    if (!match.Success) return null;

                    string accountName = match.Groups[1].Value.Trim();
                    if (string.IsNullOrWhiteSpace(accountName) ||
                        accountName.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase) ||
                        accountName.EndsWith("$", StringComparison.OrdinalIgnoreCase))
                        return null;

                    return accountName.Contains("@") ? accountName.Split('@')[0].Trim() : accountName;
                }
            }
            catch { /* silent fail */ }

            return null;
        }

        private bool IsRelevantLogonType(int logonType)
        {
            // Keep only interactive user-session logons to avoid duplicate 4624 records.
            return logonType == 2 || logonType == 7 || logonType == 10 || logonType == 11;
        }

        private string? GetUserFromSystem1074Message(string? message)
        {
            if (string.IsNullOrWhiteSpace(message))
                return null;

            try
            {
                var match = Regex.Match(message, @"on behalf of user\s+([^\r\n]+)", RegexOptions.IgnoreCase);
                if (!match.Success)
                    return null;

                string candidate = match.Groups[1].Value.Trim();
                int reasonIndex = candidate.IndexOf(" for the following reason", StringComparison.OrdinalIgnoreCase);
                if (reasonIndex > 0)
                    candidate = candidate.Substring(0, reasonIndex).Trim();

                if (candidate.Contains("\\"))
                    candidate = candidate.Substring(candidate.LastIndexOf('\\') + 1).Trim();

                if (candidate.Contains("@"))
                    candidate = candidate.Split('@')[0].Trim();

                return IsValidUsername(candidate) ? candidate : null;
            }
            catch
            {
                return null;
            }
        }

        private void StoreLast1074State(string username, DateTime eventTime, string shutdownType)
        {
            if (!IsValidUsername(username))
                return;

            lock (last1074Lock)
            {
                last1074Username = username;
                last1074EventTime = eventTime;
                last1074ShutdownType = shutdownType;
            }
        }

        private string? TryResolveUsernameFor6006(DateTime eventTime)
        {
            lock (last1074Lock)
            {
                if (string.IsNullOrWhiteSpace(last1074Username))
                    return null;

                // 6006 typically follows 1074 within a few seconds.
                if (Math.Abs((eventTime - last1074EventTime).TotalSeconds) > 10)
                    return null;

                // Keep shutdown type in state for diagnostics/future behavior tuning.
                _ = last1074ShutdownType;
                return last1074Username;
            }
        }

        private bool IsValidUsername(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
                return false;

            var invalidNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "SYSTEM", "LOCAL SERVICE", "LOCAL_SYSTEM", "NETWORK SERVICE",
                "ANONYMOUS LOGON", "Guest", "DefaultAccount", "Administrator"
            };

            if (invalidNames.Contains(username)) return false;
            if (username.EndsWith("$")) return false;

            foreach (var prefix in new[] { "DWM-", "UMFD-", "NT Service" })
                if (username.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    return false;

            return true;
        }
    }
}
