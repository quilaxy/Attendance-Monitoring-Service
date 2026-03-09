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
        private readonly string replayCheckpointPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "event-replay.checkpoint");
        private readonly PersistentEventQueue eventQueue = new PersistentEventQueue(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "event-queue.json"));

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
                            serviceStartTime = DateTime.Now;

                            SharePointIntegration.SetServiceStartTime(serviceStartTime);

                            if (securityEventLog != null)
                            {
                                securityEventLog.EntryWritten += new EntryWrittenEventHandler(OnSecurityEventWritten);
                            }

                            if (systemEventLog != null)
                            {
                                systemEventLog.EntryWritten += new EntryWrittenEventHandler(OnSystemEventWritten);
                            }

                            break;
                        }
                        catch (Exception ex)
                        {
                            lastException = ex;
                            if (i < retryCount - 1)
                            {
                                Thread.Sleep(2000);
                            }
                        }
                    }

                    if (lastException != null && securityEventLog == null)
                    {
                        throw lastException;
                    }
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


        public void StartForConsole(string[] args)
        {
            OnStart(args);
        }

        public void StopForConsole()
        {
            OnStop();
        }

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
                    SharePointIntegration.SetServiceStartTime(serviceStartTime);

                    int delaySeconds = (currentRetry == 1) ? 10 : 3;
                    Thread.Sleep(delaySeconds * 1000);

                    string publishDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "");
                    Directory.SetCurrentDirectory(publishDirectory);

                    _ = LoadConfiguration(publishDirectory);

                    cancellationTokenSource = new CancellationTokenSource();
                    cancellationToken = cancellationTokenSource.Token;

                    ReplayMissedEventsFromCheckpoint(writeRawRecord: true);

                    Thread monitoringThread = new Thread(() => MonitorEvents(cancellationToken.Value));
                    monitoringThread.IsBackground = true;
                    monitoringThread.Start();

                    EventLog.WriteEntry("Application",
                        "EmployeeLoginLogoutService started successfully",
                        EventLogEntryType.Information, 1000);

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

        private void ReplayMissedEventsFromCheckpoint(bool writeRawRecord)
        {
            try
            {
                DateTime replayTo = DateTime.Now;
                DateTime? replayFrom = LoadReplayCheckpoint();

                ReplaySecurityEvents(replayFrom, replayTo, writeRawRecord);
                ReplaySystemEvents(replayFrom, replayTo, writeRawRecord);

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
                if (DateTime.TryParse(value, null, System.Globalization.DateTimeStyles.RoundtripKind, out DateTime parsed))
                {
                    return parsed.ToLocalTime();
                }
            }
            catch
            {
                // ignore malformed checkpoint and do full replay
            }

            return null;
        }

        private void SaveReplayCheckpoint(DateTime checkpoint)
        {
            try
            {
                File.WriteAllText(replayCheckpointPath, checkpoint.ToUniversalTime().ToString("O"));
            }
            catch
            {
                // ignore checkpoint write failures
            }
        }

        private void ReplaySecurityEvents(DateTime? fromTime, DateTime toTime, bool writeRawRecord)
        {
            if (securityEventLog == null)
                return;

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

                ProcessSecurityEntryAsync(entry, writeRawRecord).GetAwaiter().GetResult();
            }
        }

        private void ReplaySystemEvents(DateTime? fromTime, DateTime toTime, bool writeRawRecord)
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

                ProcessSystemEntryAsync(entry, writeRawRecord).GetAwaiter().GetResult();
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

            try
            {
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
            catch (Exception ex)
            {
                EventLog.WriteEntry("Application",
                    $"Failed to decrypt configuration: {ex.Message}",
                    EventLogEntryType.Error, 1004);
                throw;
            }
        }

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
                Thread.Sleep(1000);

                EventLog.WriteEntry("Application",
                    "EmployeeLoginLogoutService stopped",
                    EventLogEntryType.Information, 1005);
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("Application",
                    $"Error in OnStop: {ex.Message}",
                    EventLogEntryType.Warning, 1006);
            }
        }

        private void MonitorEvents(CancellationToken cancellationToken)
        {
            try
            {
                if (securityEventLog != null)
                {
                    securityEventLog.EnableRaisingEvents = true;
                }

                if (systemEventLog != null)
                {
                    systemEventLog.EnableRaisingEvents = true;
                }

                Task.Run(() => CleanupOldRecordsTask(cancellationToken), cancellationToken);
                Task.Run(() => ProcessQueuedEventsTask(cancellationToken), cancellationToken);

                while (!cancellationToken.IsCancellationRequested)
                {
                    Thread.Sleep(5000);
                }
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("Application",
                    $"Error in MonitorEvents: {ex.Message}",
                    EventLogEntryType.Error, 1007);
            }
        }

        private async Task ProcessQueuedEventsTask(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    QueuedAttendanceEvent? nextEvent = await eventQueue.PeekAsync(cancellationToken);
                    if (nextEvent == null)
                    {
                        await Task.Delay(TimeSpan.FromSeconds(5), cancellationToken);
                        continue;
                    }

                    bool sent = await TryDispatchQueuedEventAsync(nextEvent);
                    if (sent)
                    {
                        await eventQueue.RemoveByIdAsync(nextEvent.QueueId, cancellationToken);
                        continue;
                    }

                    await Task.Delay(TimeSpan.FromSeconds(10), cancellationToken);
                }
                catch (TaskCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    EventLog.WriteEntry("Application",
                        $"Error in ProcessQueuedEventsTask: {ex.Message}",
                        EventLogEntryType.Warning, 1015);

                    try
                    {
                        await Task.Delay(TimeSpan.FromSeconds(15), cancellationToken);
                    }
                    catch (TaskCanceledException)
                    {
                        break;
                    }
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
                {
                    rawTask = sharePoint.AddRecordToSharePointAsync(accessToken, item.Username, item.EventTime, item.EventId, item.EventType, item.ComputerName);
                }

                Task? summaryTask = null;
                if (item.EventId == 4624)
                {
                    DateTime loginTime = item.LoginTime ?? item.EventTime;
                    summaryTask = sharePoint.UpsertDailySummaryLoginAsync(accessToken, item.Username, item.ComputerName, loginTime);
                }
                else if (item.EventId == 1074 || item.EventId == 6006 || item.EventId == 4647 || item.EventId == 6008 || item.EventId == 41)
                {
                    DateTime shutdownTime = item.ShutdownTime ?? item.EventTime;
                    summaryTask = sharePoint.TryUpdateDailySummaryShutdownAsync(accessToken, item.Username, item.ComputerName, shutdownTime, item.EventId, item.EventType);
                }

                if (rawTask != null && summaryTask != null)
                {
                    await Task.WhenAll(rawTask, summaryTask);
                }
                else if (rawTask != null)
                {
                    await rawTask;
                }
                else if (summaryTask != null)
                {
                    await summaryTask;
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

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
                    {
                        nextRun = nextRun.AddDays(1);
                    }

                    DateTime todaysCleanup = now.Date.AddHours(cleanupHour);
                    bool missedCleanup = (now.Hour > cleanupHour) && (now.Date == todaysCleanup.Date);

                    if (missedCleanup)
                    {
                        int randomDelay = new Random(Environment.MachineName.GetHashCode()).Next(0, 300000);
                        await Task.Delay(randomDelay, cancellationToken);

                        var sharePointMissed = new SharePointIntegration();
                        await sharePointMissed.CleanupOldRecordsAsync(retentionMonths);
                    }

                    TimeSpan delay = nextRun - now;
                    await Task.Delay(delay, cancellationToken);

                    int scheduledDelay = new Random(Environment.MachineName.GetHashCode()).Next(0, 300000);
                    await Task.Delay(scheduledDelay, cancellationToken);

                    var sharePoint = new SharePointIntegration();
                    await sharePoint.CleanupOldRecordsAsync(retentionMonths);
                }
                catch (TaskCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    EventLog.WriteEntry("Application",
                        $"Error in CleanupOldRecordsTask: {ex.Message}",
                        EventLogEntryType.Warning, 1008);

                    try
                    {
                        await Task.Delay(TimeSpan.FromHours(1), cancellationToken);
                    }
                    catch (TaskCanceledException)
                    {
                        break;
                    }
                }
            }
        }

        private async void OnSecurityEventWritten(object sender, EntryWrittenEventArgs e)
        {
            if (e?.Entry == null)
                return;

            await ProcessSecurityEntryAsync(e.Entry, writeRawRecord: true);
        }

        private async Task ProcessSecurityEntryAsync(EventLogEntry log, bool writeRawRecord)
        {
            try
            {
                if (log.Message == null)
                    return;

                int eventId = unchecked((int)log.InstanceId);

                if (eventId != 4624 && eventId != 4647)
                    return;

                DateTime eventTime = log.TimeGenerated;
                string computerName = log.MachineName;

                string eventMessage = log.Message;
                string? username = GetUsernameFromEvent(eventMessage, eventId);

                if (string.IsNullOrEmpty(username) || !IsValidUsername(username))
                    return;

                if (eventId == 4624)
                {
                    lock (userLock)
                    {
                        lastActiveUser = username;
                    }
                }

                await ProcessEvent(eventId, username, eventTime, computerName, "Security", null, writeRawRecord);
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("Application",
                    $"Error in OnSecurityEventWritten: {ex.Message}",
                    EventLogEntryType.Warning, 1009);
            }
        }

        private string? GetMostRecentUser(DateTime beforeTime)
        {
            try
            {
                DateTime lookbackTime = beforeTime.AddHours(-1);
                EventLog secLog = new EventLog("Security");

                int checkCount = 0;
                int maxCheck = 50;

                for (int i = secLog.Entries.Count - 1; i >= 0 && checkCount < maxCheck; i--)
                {
                    checkCount++;
                    EventLogEntry entry = secLog.Entries[i];

                    if ((unchecked((int)entry.InstanceId) == 4624 || unchecked((int)entry.InstanceId) == 4647) &&
                        entry.TimeGenerated >= lookbackTime &&
                        entry.TimeGenerated <= beforeTime)
                    {
                        if (entry.Message != null)
                        {
                            string? username = GetUsernameFromEvent(entry.Message, unchecked((int)entry.InstanceId));

                            if (!string.IsNullOrEmpty(username) && IsValidUsername(username))
                            {
                                return username;
                            }
                        }
                    }
                }
            }
            catch
            {
                // Silent fail
            }

            return null;
        }

        private async void OnSystemEventWritten(object sender, EntryWrittenEventArgs e)
        {
            if (e?.Entry == null)
                return;

            await ProcessSystemEntryAsync(e.Entry, writeRawRecord: true);
        }

        private async Task ProcessSystemEntryAsync(EventLogEntry log, bool writeRawRecord)
        {
            try
            {
                if (log.Message == null)
                    return;

                int eventId = unchecked((int)log.InstanceId);

                if (eventId != 1074 && eventId != 6006 && eventId != 6008 && eventId != 41 && eventId != 42)
                    return;

                DateTime eventTime = log.TimeGenerated;
                string computerName = log.MachineName;

                string? username;

                lock (userLock)
                {
                    username = lastActiveUser;
                }

                if (string.IsNullOrEmpty(username))
                {
                    username = GetMostRecentUser(eventTime);

                    if (string.IsNullOrEmpty(username))
                        return;
                }

                if (eventId == 42)
                {
                    SharePointIntegration.MarkSleepEvent(eventTime);
                }

                string? eventMessage = (eventId == 1074) ? log.Message : null;
                await ProcessEvent(eventId, username, eventTime, computerName, "System", eventMessage, writeRawRecord);
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("Application",
                    $"Error in OnSystemEventWritten: {ex.Message}",
                    EventLogEntryType.Warning, 1010);
            }
        }

        private string ParseShutdownType(string? eventMessage)
        {
            if (string.IsNullOrEmpty(eventMessage))
                return "Shutdown/Restart Initiated";

            try
            {
                var regex = new Regex(@"Shut-down Type:\s*([^\r\n]+)", RegexOptions.IgnoreCase);
                var match = regex.Match(eventMessage);

                if (match.Success)
                {
                    string shutdownType = match.Groups[1].Value.Trim().ToLower();

                    if (shutdownType.Contains("restart") || shutdownType.Contains("reboot"))
                    {
                        return "Restart Initiated";
                    }
                    else if (shutdownType.Contains("power off") || shutdownType.Contains("shutdown"))
                    {
                        return "Shutdown Initiated";
                    }
                }

                return "Shutdown/Restart Initiated";
            }
            catch
            {
                return "Shutdown/Restart Initiated";
            }
        }

        private async Task ProcessEvent(int eventId, string username, DateTime eventTime, string computerName, string logType, string? eventMessage = null, bool writeRawRecord = true)
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
                        41 => "System Crash",
                        42 => "Sleep",
                        _ => "Unknown System Event"
                    },
                    _ => "Unknown Event"
                };

                if (eventTime.Kind == DateTimeKind.Unspecified)
                {
                    eventTime = DateTime.SpecifyKind(eventTime, DateTimeKind.Local);
                }

                if (eventId == 1074 || eventId == 6006 || eventId == 4647 || eventId == 6008 || eventId == 41 || eventId == 42)
                {
                    SharePointIntegration.MarkShutdownEvent(eventTime);
                }

                DateTime? loginTime = null;
                DateTime? expectedTimeOut = null;
                DateTime? shutdownTime = null;
                string? shutdownType = null;

                if (eventId == 4624)
                {
                    loginTime = eventTime;
                    expectedTimeOut = eventTime.AddHours(9);
                }
                else if (eventId == 1074 || eventId == 6006 || eventId == 4647 || eventId == 6008 || eventId == 41)
                {
                    shutdownTime = eventTime;
                    shutdownType = $"{eventId} - {eventType}";
                }

                var queuedEvent = new QueuedAttendanceEvent
                {
                    QueueId = Guid.NewGuid().ToString("N"),
                    EventId = eventId,
                    Username = username,
                    EventTime = eventTime,
                    ComputerName = computerName,
                    EventType = eventType,
                    LoginTime = loginTime,
                    ExpectedTimeOut = expectedTimeOut,
                    ShutdownTime = shutdownTime,
                    ShutdownType = shutdownType,
                    WriteRawRecord = writeRawRecord
                };

                await eventQueue.EnqueueAsync(queuedEvent);
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("Application",
                    $"Error in ProcessEvent: {ex.Message}",
                    EventLogEntryType.Warning, 1011);
            }
        }

        private string? GetUsernameFromEvent(string message, int eventId)
        {
            try
            {
                if (eventId == 4624)
                {
                    int newLogonIndex = message.IndexOf("New Logon:");
                    if (newLogonIndex == -1)
                        return null;

                    string newLogonSection = message.Substring(newLogonIndex);

                    var regexAccountName = new Regex(@"Account Name:\s*([^\r\n]+)");
                    var matchAccountName = regexAccountName.Match(newLogonSection);

                    if (matchAccountName.Success)
                    {
                        string accountName = matchAccountName.Groups[1].Value.Trim();

                        if (string.IsNullOrWhiteSpace(accountName) ||
                            accountName.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase) ||
                            accountName.Equals("-", StringComparison.OrdinalIgnoreCase) ||
                            accountName.EndsWith("$", StringComparison.OrdinalIgnoreCase))
                        {
                            return null;
                        }

                        string normalizedUsername = accountName;
                        if (accountName.Contains("@"))
                        {
                            normalizedUsername = accountName.Split('@')[0].Trim();
                        }

                        return normalizedUsername;
                    }
                }

                if (eventId == 4647)
                {
                    int subjectIndex = message.IndexOf("Subject:");
                    if (subjectIndex == -1)
                        return null;

                    string subjectSection = message.Substring(subjectIndex);

                    var regexAccountName = new Regex(@"Account Name:\s*([^\r\n]+)");
                    var matchAccountName = regexAccountName.Match(subjectSection);

                    if (matchAccountName.Success)
                    {
                        string accountName = matchAccountName.Groups[1].Value.Trim();

                        if (string.IsNullOrWhiteSpace(accountName) ||
                            accountName.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase) ||
                            accountName.EndsWith("$", StringComparison.OrdinalIgnoreCase))
                        {
                            return null;
                        }

                        string normalizedUsername = accountName;
                        if (accountName.Contains("@"))
                        {
                            normalizedUsername = accountName.Split('@')[0].Trim();
                        }

                        return normalizedUsername;
                    }
                }
            }
            catch
            {
                // Silent fail
            }

            return null;
        }

        private bool IsValidUsername(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
                return false;

            var invalidUsernames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "SYSTEM", "LOCAL SERVICE", "LOCAL_SYSTEM", "NETWORK SERVICE",
                "ANONYMOUS LOGON", "Guest", "DefaultAccount", "Administrator"
            };

            if (invalidUsernames.Contains(username))
                return false;

            if (username.EndsWith("$"))
                return false;

            var prefixConditions = new string[]
            {
                "DWM-", "UMFD-", "NT Service"
            };

            foreach (var prefix in prefixConditions)
            {
                if (username.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    return false;
            }

            return true;
        }
    }
}
