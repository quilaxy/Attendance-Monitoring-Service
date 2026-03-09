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
        private DateTime serviceStartTime;

        private readonly string replayCheckpointPath =
            Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "event-replay.checkpoint");

        private readonly PersistentEventQueue eventQueue =
            new PersistentEventQueue(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "event-queue.json"));

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

                    EventLog.WriteEntry("Attendance-Service",
                        "Service started successfully.",
                        EventLogEntryType.Information, 0);

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
        }

        // ─── Replay missed events ────────────────────────────────────────────────

        private void ReplayMissedEventsFromCheckpoint()
        {
            try
            {
                DateTime replayTo = DateTime.Now;
                DateTime? replayFrom = LoadReplayCheckpoint();

                ReplaySecurityEvents(replayFrom, replayTo);
                ReplaySystemEvents(replayFrom, replayTo);

                SaveReplayCheckpoint(replayTo);
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("Application",
                    $"Error while replaying startup events: {ex.Message}",
                    EventLogEntryType.Warning, 1014);
            }
        }

        private DateTime? LoadReplayCheckpoint()
        {
            try
            {
                if (!File.Exists(replayCheckpointPath))
                    return null;

                string value = File.ReadAllText(replayCheckpointPath).Trim();
                if (DateTime.TryParse(value, null,
                        System.Globalization.DateTimeStyles.RoundtripKind, out DateTime parsed))
                    return parsed.ToLocalTime();
            }
            catch { /* ignore malformed checkpoint */ }

            return null;
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

            // Walk backwards; break once we pass fromTime
            for (int i = securityEventLog.Entries.Count - 1; i >= 0; i--)
            {
                EventLogEntry entry = securityEventLog.Entries[i];
                DateTime eventTime = entry.TimeGenerated;

                if (fromTime.HasValue && eventTime <= fromTime.Value)
                    break;

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
                    break;

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
                    if (count == 0) break;
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

                    bool sent = await TryDispatchQueuedEventAsync(next);
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

        private async Task<bool> TryDispatchQueuedEventAsync(QueuedAttendanceEvent item)
        {
            try
            {
                var sharePoint = new SharePointIntegration();
                string? accessToken = await sharePoint.GetAccessTokenAsync(item.EventTime, item.EventId);
                if (string.IsNullOrEmpty(accessToken))
                    return false;

                Task? rawTask = null;
                if (item.WriteRawRecord)
                    rawTask = sharePoint.AddRecordToSharePointAsync(
                        accessToken, item.Username, item.EventTime,
                        item.EventId, item.EventType, item.ComputerName);

                Task? summaryTask = null;
                if (item.EventId == 4624)
                {
                    summaryTask = sharePoint.UpsertDailySummaryLoginAsync(
                        accessToken, item.Username, item.ComputerName,
                        item.LoginTime ?? item.EventTime);
                }
                else if (item.EventId == 1074 || item.EventId == 6006 ||
                         item.EventId == 4647 || item.EventId == 6008 || item.EventId == 41)
                {
                    summaryTask = sharePoint.TryUpdateDailySummaryShutdownAsync(
                        accessToken, item.Username, item.ComputerName,
                        item.ShutdownTime ?? item.EventTime,
                        item.EventId, item.EventType);
                }

                if (rawTask != null && summaryTask != null)
                    await Task.WhenAll(rawTask, summaryTask);
                else if (rawTask != null)
                    await rawTask;
                else if (summaryTask != null)
                    await summaryTask;

                return true;
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
                        await new SharePointIntegration().CleanupOldRecordsAsync(retentionMonths);
                    }

                    await Task.Delay(nextRun - DateTime.Now, cancellationToken);

                    int scheduledDelay = new Random(Environment.MachineName.GetHashCode()).Next(0, 300000);
                    await Task.Delay(scheduledDelay, cancellationToken);
                    await new SharePointIntegration().CleanupOldRecordsAsync(retentionMonths);
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
                if (log.Message == null) return;

                int eventId = unchecked((int)log.InstanceId);
                if (eventId != 4624 && eventId != 4647) return;

                DateTime eventTime = log.TimeGenerated;
                string computerName = log.MachineName;
                string eventMessage = log.Message;

                // Parse logon type (only relevant for 4624)
                int logonType = 0;
                if (eventId == 4624)
                    logonType = ParseLogonType(eventMessage);

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
                if (log.Message == null) return;

                int eventId = unchecked((int)log.InstanceId);
                if (eventId != 1074 && eventId != 6006 && eventId != 6008 && eventId != 41 && eventId != 42)
                    return;

                DateTime eventTime = log.TimeGenerated;
                string computerName = log.MachineName;

                string? username;
                lock (userLock)
                    username = lastActiveUser;

                if (string.IsNullOrEmpty(username))
                {
                    username = GetMostRecentUser(eventTime);
                    if (string.IsNullOrEmpty(username))
                        return;
                }

                if (eventId == 42)
                    SharePointIntegration.MarkSleepEvent(eventTime);

                string? eventMessage = (eventId == 1074) ? log.Message : null;
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
                        4624 => "User Login",
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
                DateTime lookbackTime = beforeTime.AddHours(-1);
                EventLog secLog = new EventLog("Security");
                int checkCount = 0;

                for (int i = secLog.Entries.Count - 1; i >= 0 && checkCount < 50; i--)
                {
                    checkCount++;
                    EventLogEntry entry = secLog.Entries[i];

                    if ((unchecked((int)entry.InstanceId) == 4624 ||
                         unchecked((int)entry.InstanceId) == 4647) &&
                        entry.TimeGenerated >= lookbackTime &&
                        entry.TimeGenerated <= beforeTime &&
                        entry.Message != null)
                    {
                        string? u = GetUsernameFromEvent(entry.Message, unchecked((int)entry.InstanceId));
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
