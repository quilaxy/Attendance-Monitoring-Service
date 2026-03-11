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

        private readonly string stopCheckpointBackupPath =
            Path.Combine(DataDirectory, "event-stop.checkpoint.bak");

        private readonly PersistentEventQueue eventQueue =
            new PersistentEventQueue(Path.Combine(DataDirectory, "event-queue.json"));

        public LoginLogoutMonitorService()
        {
            // Allow OnShutdown() to be called during system shutdown/restart.
            // Without this, ServiceBase never invokes OnShutdown() and the checkpoint is lost.
            CanShutdown = true;

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

                EventLog.WriteEntry("Application",
                    $"ReplayMissedEvents: replayFrom={replayFrom?.ToString("O") ?? "(none)"} replayTo={replayTo:O}",
                    EventLogEntryType.Information, 1034);

                if (replayFrom.HasValue)
                {
                    // Security events first so lastActiveUser is populated before system events run
                    ReplaySecurityEvents(replayFrom, replayTo);
                    ReplaySystemEvents(replayFrom, replayTo);
                }
                else
                {
                    EventLog.WriteEntry("Application",
                        "ReplayMissedEvents: no checkpoint found, skipping replay.",
                        EventLogEntryType.Information, 1029);
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
                // Primary checkpoint
                DateTime? checkpoint = TryLoadCheckpoint(stopCheckpointPath);
                if (checkpoint.HasValue)
                {
                    EventLog.WriteEntry("Application",
                        $"LoadStopCheckpoint: loaded from primary '{stopCheckpointPath}' → {checkpoint.Value:O}",
                        EventLogEntryType.Information, 1024);
                    return checkpoint;
                }

                EventLog.WriteEntry("Application",
                    $"LoadStopCheckpoint: primary not found at '{stopCheckpointPath}', trying backup.",
                    EventLogEntryType.Warning, 1023);

                // Backup checkpoint (in case primary write was interrupted mid-shutdown)
                checkpoint = TryLoadCheckpoint(stopCheckpointBackupPath);
                if (checkpoint.HasValue)
                {
                    EventLog.WriteEntry("Application",
                        $"LoadStopCheckpoint: loaded from backup '{stopCheckpointBackupPath}' → {checkpoint.Value:O}",
                        EventLogEntryType.Warning, 1023);
                    return checkpoint;
                }

                // Last-resort: derive from replay checkpoint -5 min so we don't miss events
                // written right before the previous service start
                DateTime? replayCheckpoint = TryLoadCheckpoint(replayCheckpointPath);
                if (replayCheckpoint.HasValue)
                {
                    DateTime derived = replayCheckpoint.Value.AddMinutes(-5);
                    EventLog.WriteEntry("Application",
                        $"LoadStopCheckpoint: both stop checkpoints missing — deriving from replay checkpoint " +
                        $"({replayCheckpoint.Value:O}) -5min → {derived:O}",
                        EventLogEntryType.Warning, 1023);
                    return derived;
                }

                EventLog.WriteEntry("Application",
                    "LoadStopCheckpoint: no checkpoint found (primary, backup, or replay) — replay skipped.",
                    EventLogEntryType.Warning, 1023);
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("Application",
                    $"LoadStopCheckpoint: exception {ex.GetType().Name}: {ex.Message}",
                    EventLogEntryType.Warning, 1027);
            }

            return null;
        }

        /// <summary>Reads and parses a checkpoint file. Returns null if missing or malformed.</summary>
        private static DateTime? TryLoadCheckpoint(string path)
        {
            if (!File.Exists(path))
                return null;

            string value = File.ReadAllText(path).Trim();
            if (!DateTime.TryParse(value, null,
                    System.Globalization.DateTimeStyles.RoundtripKind, out DateTime parsed))
                return null;

            return parsed.ToLocalTime();
        }

        private void SaveStopCheckpoint(DateTime checkpoint)
        {
            try
            {
                string? dir = Path.GetDirectoryName(stopCheckpointPath);

                EventLog.WriteEntry("Application",
                    $"SaveStopCheckpoint: dir='{dir}' path='{stopCheckpointPath}'",
                    EventLogEntryType.Information, 1020);

                if (!string.IsNullOrWhiteSpace(dir) && !Directory.Exists(dir))
                {
                    Directory.CreateDirectory(dir);
                    EventLog.WriteEntry("Application",
                        $"SaveStopCheckpoint: created directory '{dir}'",
                        EventLogEntryType.Information, 1021);
                }

                string content = checkpoint.ToUniversalTime().ToString("O");

                // Write atomically via temp+rename so the file is never half-written
                // if Windows kills the process mid-write during system shutdown.
                // Primary path:
                string tempPrimary = stopCheckpointPath + ".tmp";
                File.WriteAllText(tempPrimary, content);
                File.Move(tempPrimary, stopCheckpointPath, overwrite: true);

                // Backup path (same trick):
                string tempBackup = stopCheckpointBackupPath + ".tmp";
                File.WriteAllText(tempBackup, content);
                File.Move(tempBackup, stopCheckpointBackupPath, overwrite: true);

                EventLog.WriteEntry("Application",
                    $"SaveStopCheckpoint: written '{content}' to primary + backup.",
                    EventLogEntryType.Information, 1022);
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("Application",
                    $"Failed to save stop checkpoint: {ex.GetType().Name}: {ex.Message} | Path='{stopCheckpointPath}'",
                    EventLogEntryType.Warning, 1017);
            }
        }

        private void SaveReplayCheckpoint(DateTime checkpoint)
        {
            try
            {
                string? dir = Path.GetDirectoryName(replayCheckpointPath);
                if (!string.IsNullOrWhiteSpace(dir) && !Directory.Exists(dir))
                    Directory.CreateDirectory(dir);

                File.WriteAllText(replayCheckpointPath,
                    checkpoint.ToUniversalTime().ToString("O"));
            }
            catch { /* ignore write failures */ }
        }

        private void ReplaySecurityEvents(DateTime? fromTime, DateTime toTime)
        {
            if (securityEventLog == null)
                return;

            // GUARD: fromTime null means no checkpoint exists — do NOT replay.
            // Without a lower bound we would re-import the entire Security log history.
            if (!fromTime.HasValue)
            {
                EventLog.WriteEntry("Application",
                    "ReplaySecurityEvents: fromTime is null — skipping to avoid full log flood.",
                    EventLogEntryType.Warning, 1035);
                return;
            }

            // Collect and sort ascending (oldest-first) for consistent ordering.
            var entries = new List<(DateTime Time, EventLogEntry Entry, int EventId)>();

            for (int i = securityEventLog.Entries.Count - 1; i >= 0; i--)
            {
                EventLogEntry entry = securityEventLog.Entries[i];
                DateTime eventTime = entry.TimeGenerated;

                if (eventTime <= fromTime.Value)  // fromTime non-null guaranteed by guard above
                    continue;

                if (eventTime > toTime)
                    continue;

                int eventId = GetNormalizedEventId(entry);
                if (eventId != 4624 && eventId != 4647)
                    continue;

                // Pre-filter 4624: skip irrelevant logon types early
                if (eventId == 4624 && entry.Message != null)
                {
                    int lt = ParseLogonType(entry.Message);
                    if (!IsRelevantLogonType(lt))
                        continue;
                }

                entries.Add((eventTime, entry, eventId));
            }

            EventLog.WriteEntry("Application",
                $"ReplaySecurityEvents: found {entries.Count} security events between {fromTime:O} and {toTime:O}.",
                EventLogEntryType.Information, 1032);

            entries.Sort((a, b) => a.Time.CompareTo(b.Time));

            foreach (var (time, entry, eventId) in entries)
            {
                EventLog.WriteEntry("Application",
                    $"ReplaySecurityEvents: processing EventId={eventId} at {time:O}",
                    EventLogEntryType.Information, 1033);

                ProcessSecurityEntryAsync(entry, writeRawRecord: true).GetAwaiter().GetResult();
            }
        }

        private void ReplaySystemEvents(DateTime? fromTime, DateTime toTime)
        {
            if (systemEventLog == null)
                return;

            // GUARD: fromTime null means no checkpoint — skip to avoid full log flood.
            if (!fromTime.HasValue)
            {
                EventLog.WriteEntry("Application",
                    "ReplaySystemEvents: fromTime is null — skipping to avoid full log flood.",
                    EventLogEntryType.Warning, 1036);
                return;
            }

            // Collect matching entries first, then sort ASCENDING (oldest first).
            // CRITICAL: 1074 must be processed before 6006 so TryResolve1074StateFor6006
            // can find the username set by StoreLast1074State().
            var entries = new List<(DateTime Time, EventLogEntry Entry, int EventId)>();

            for (int i = systemEventLog.Entries.Count - 1; i >= 0; i--)
            {
                EventLogEntry entry = systemEventLog.Entries[i];
                DateTime eventTime = entry.TimeGenerated;

                if (eventTime <= fromTime.Value)  // fromTime non-null guaranteed by guard above
                    continue;

                if (eventTime > toTime)
                    continue;

                int eventId = GetNormalizedEventId(entry);
                if (eventId != 1074 && eventId != 6006 && eventId != 6008 && eventId != 41 && eventId != 42)
                    continue;

                entries.Add((eventTime, entry, eventId));
            }

            EventLog.WriteEntry("Application",
                $"ReplaySystemEvents: found {entries.Count} system events between {fromTime:O} and {toTime:O}.",
                EventLogEntryType.Information, 1030);

            // Sort oldest-first so 1074 is always processed before its paired 6006
            entries.Sort((a, b) => a.Time.CompareTo(b.Time));

            foreach (var (time, entry, eventId) in entries)
            {
                EventLog.WriteEntry("Application",
                    $"ReplaySystemEvents: processing EventId={eventId} at {time:O} Source={entry.Source}",
                    EventLogEntryType.Information, 1031);

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

        protected override void OnStop() => HandleServiceStopping("OnStop");

        /// <summary>
        /// Called by SCM during Windows system shutdown/restart (requires CanShutdown = true).
        /// OnStop() is NOT guaranteed to be called in that scenario.
        /// </summary>
        protected override void OnShutdown() => HandleServiceStopping("OnShutdown");

        private void HandleServiceStopping(string caller)
        {
            try
            {
                // ── Step 1: Request extra shutdown time from SCM immediately.
                // Windows system shutdown gives services only ~5 seconds by default.
                // RequestAdditionalTime tells SCM we need more — prevents premature kill.
                RequestAdditionalTime(8000);

                // ── Step 2: Save checkpoint FIRST, before anything else.
                // If Windows kills us after this line, replay will still cover missed events.
                DateTime stopCheckpoint = DateTime.Now.AddMinutes(-5);

                EventLog.WriteEntry("Application",
                    $"{caller}: saving checkpoint {stopCheckpoint:O} to {stopCheckpointPath}",
                    EventLogEntryType.Information, 1018);

                SaveStopCheckpoint(stopCheckpoint);

                EventLog.WriteEntry("Application",
                    $"{caller}: checkpoint saved.",
                    EventLogEntryType.Information, 1019);

                // ── Step 3: Stop listening for new events
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

                // ── Step 4: Brief wait for any in-flight dispatch to finish.
                // Keep this short (≤5s total) — checkpoint is already saved so
                // any un-sent events will be replayed on next start anyway.
                int waited = 0;
                while (waited < 4000)
                {
                    int processing = Volatile.Read(ref activeDispatchCount);
                    if (processing == 0) break;
                    Thread.Sleep(200);
                    waited += 200;
                }

                EventLog.WriteEntry("Attendance-Service",
                    $"Service has been successfully shut down ({caller}).",
                    EventLogEntryType.Information, 0);
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("Application",
                    $"Error in {caller}: {ex.Message}",
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
                {
                    EventLog.WriteEntry("Application",
                        $"[DISPATCH] Token null — skipping queueId={item.QueueId} eventId={item.EventId} user={item.Username}",
                        EventLogEntryType.Warning, 4001);
                    return false;
                }

                bool needsRaw     = item.WriteRawRecord && !item.RawRecordDispatched;
                bool needsSummary = ShouldProcessSummary(item) && !item.SummaryDispatched;

                EventLog.WriteEntry("Application",
                    $"[DISPATCH] queueId={item.QueueId} eventId={item.EventId} user={item.Username} " +
                    $"time={item.EventTime:O} needsRaw={needsRaw} needsSummary={needsSummary} " +
                    $"eventType='{item.EventType}' shutdownType='{item.ShutdownType ?? "(null)"}'",
                    EventLogEntryType.Information, 4002);

                if (needsRaw)
                {
                    await sharePoint.AddRecordToSharePointAsync(
                        accessToken, item.Username, item.EventTime,
                        item.EventId, item.EventType, item.ComputerName);

                    await eventQueue.UpdateDispatchStateAsync(item.QueueId, rawRecordDispatched: true);
                    item.RawRecordDispatched = true;
                    EventLog.WriteEntry("Application",
                        $"[DISPATCH] Raw record sent: queueId={item.QueueId} eventId={item.EventId} user={item.Username}",
                        EventLogEntryType.Information, 4003);
                }

                if (needsSummary)
                {
                    if (item.EventId == 4624)
                    {
                        EventLog.WriteEntry("Application",
                            $"[DISPATCH] Sending summary login: user={item.Username} computer={item.ComputerName} " +
                            $"loginTime={item.LoginTime?.ToString("O") ?? item.EventTime.ToString("O")}",
                            EventLogEntryType.Information, 4004);

                        await sharePoint.UpsertDailySummaryLoginAsync(
                            accessToken, item.Username, item.ComputerName,
                            item.LoginTime ?? item.EventTime);
                    }
                    else
                    {
                        EventLog.WriteEntry("Application",
                            $"[DISPATCH] Sending summary shutdown: user={item.Username} computer={item.ComputerName} " +
                            $"shutdownTime={item.ShutdownTime?.ToString("O") ?? item.EventTime.ToString("O")} " +
                            $"eventId={item.EventId} eventType='{item.EventType}'",
                            EventLogEntryType.Information, 4005);

                        await sharePoint.TryUpdateDailySummaryShutdownAsync(
                            accessToken, item.Username, item.ComputerName,
                            item.ShutdownTime ?? item.EventTime,
                            item.EventId, item.EventType);
                    }

                    await eventQueue.UpdateDispatchStateAsync(item.QueueId, summaryDispatched: true);
                    item.SummaryDispatched = true;
                    EventLog.WriteEntry("Application",
                        $"[DISPATCH] Summary dispatched: queueId={item.QueueId} eventId={item.EventId} user={item.Username}",
                        EventLogEntryType.Information, 4006);
                }

                bool doneRaw     = !item.WriteRawRecord || item.RawRecordDispatched;
                bool doneSummary = !ShouldProcessSummary(item) || item.SummaryDispatched;

                EventLog.WriteEntry("Application",
                    $"[DISPATCH] Done: queueId={item.QueueId} doneRaw={doneRaw} doneSummary={doneSummary}",
                    EventLogEntryType.Information, 4007);

                return doneRaw && doneSummary;
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("Application",
                    $"Dispatch failed: queueId={item.QueueId} eventId={item.EventId} user={item.Username} " +
                    $"time={item.EventTime:O} error={ex.GetType().Name}: {ex.Message}",
                    EventLogEntryType.Warning, 1028);
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
                int eventId = GetNormalizedEventId(log);
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
                int eventId = GetNormalizedEventId(log);
                if (eventId != 1074 && eventId != 6006 && eventId != 6008 && eventId != 41 && eventId != 42)
                    return;

                DateTime eventTime = log.TimeGenerated;
                string computerName = log.MachineName;

                // ── 1074: Null-message guard + message preview for debugging ────────
                if (eventId == 1074)
                {
                    if (log.Message == null)
                    {
                        EventLog.WriteEntry("Application",
                            $"[DBG-1074] EventId=1074 at {eventTime:O} has NULL message — skipping.",
                            EventLogEntryType.Warning, 2001);
                        return;
                    }

                    // Log first 300 chars of message so we can verify regex match
                    string preview = log.Message.Length > 300 ? log.Message.Substring(0, 300) : log.Message;
                    EventLog.WriteEntry("Application",
                        $"[DBG-1074] at {eventTime:O} | MessagePreview: {preview}",
                        EventLogEntryType.Information, 2002);
                }

                string? eventMessage = (eventId == 1074) ? log.Message : null;
                string? username = (eventId == 1074) ? GetUserFromSystem1074Message(eventMessage) : null;

                if (eventId == 1074)
                {
                    EventLog.WriteEntry("Application",
                        $"[DBG-1074] GetUserFromSystem1074Message returned: '{username ?? "(null)"}'",
                        EventLogEntryType.Information, 2003);
                }

                if (eventId == 1074 && !string.IsNullOrEmpty(username))
                {
                    string shutdownType = ParseShutdownType(eventMessage);
                    StoreLast1074State(username, eventTime, shutdownType);
                    EventLog.WriteEntry("Application",
                        $"[DBG-1074] Stored state: Username={username} ShutdownType={shutdownType} Time={eventTime:O}",
                        EventLogEntryType.Information, 2004);
                }

                if (eventId == 6006)
                {
                    var (resolved, confirmed1074ShutdownType) = TryResolve1074StateFor6006(eventTime);
                    EventLog.WriteEntry("Application",
                        $"[DBG-6006] at {eventTime:O} | resolved='{resolved ?? "(null)"}' " +
                        $"confirmed1074ShutdownType='{confirmed1074ShutdownType ?? "(unconfirmed)"}'",
                        EventLogEntryType.Information, 2005);
                    username = resolved ?? username;
                    // Pass confirmed1074ShutdownType via eventMessage slot for 6006 context.
                    // ProcessEvent will use this to set the correct shutdownType on the queued event.
                    eventMessage = confirmed1074ShutdownType;
                }

                if (string.IsNullOrEmpty(username))
                {
                    string? fromLock;
                    lock (userLock)
                        fromLock = lastActiveUser;

                    EventLog.WriteEntry("Application",
                        $"[DBG-{eventId}] username null after event parse, lastActiveUser='{fromLock ?? "(empty)"}'",
                        EventLogEntryType.Information, 2006);

                    username = fromLock;
                }

                if (string.IsNullOrEmpty(username))
                {
                    string? fromLog = GetMostRecentUser(eventTime);
                    EventLog.WriteEntry("Application",
                        $"[DBG-{eventId}] username still null, GetMostRecentUser returned: '{fromLog ?? "(null)"}'",
                        EventLogEntryType.Information, 2007);

                    username = fromLog;
                    if (string.IsNullOrEmpty(username))
                    {
                        EventLog.WriteEntry("Application",
                            $"[DBG-{eventId}] DROPPING event at {eventTime:O} — no username could be resolved.",
                            EventLogEntryType.Warning, 2008);
                        return;
                    }
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
                        // For 6006: eventMessage carries the confirmed 1074 shutdown type (if paired).
                        // If null, we don't know the cause — label it as unconfirmed.
                        6006 => !string.IsNullOrEmpty(eventMessage)
                                    ? $"Shutdown Completed ({eventMessage})"
                                    : "Shutdown Completed (type unconfirmed)",
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

                    int secEventId = GetNormalizedEventId(entry);
                    if ((secEventId == 4624 || secEventId == 4647) &&
                        entry.TimeGenerated >= lookbackTime &&
                        entry.TimeGenerated <= beforeTime &&
                        entry.Message != null)
                    {
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

        /// <summary>
        /// Returns the normalized 16-bit Event ID as shown in Event Viewer.
        /// EventLogEntry.InstanceId can include qualifier/facility bits in the high 16 bits
        /// for some channels (e.g. Security log), causing unchecked casts to return wrong values.
        /// EventLogEntry.EventID always returns the low 16-bit identifier.
        /// </summary>
        private static int GetNormalizedEventId(EventLogEntry entry)
        {
            return unchecked((int)(entry.InstanceId & 0xFFFF));
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
                // Pattern 1 (English): "on behalf of user DOMAIN\User for the following reason"
                var match = Regex.Match(message, @"on behalf of user\s+([^\r\n]+)", RegexOptions.IgnoreCase);

                // Pattern 2 (non-English locale): "DOMAIN\Username for the following reason"
                // e.g. Indonesian Windows: "atas nama pengguna DOMAIN\User untuk alasan berikut"
                if (!match.Success)
                    match = Regex.Match(message, @"\\([^\\\s]+)\s+for the following reason", RegexOptions.IgnoreCase);

                if (match.Success)
                {
                    string candidate = match.Groups[1].Value.Trim();
                    int reasonIndex = candidate.IndexOf(" for the following reason", StringComparison.OrdinalIgnoreCase);
                    if (reasonIndex > 0)
                        candidate = candidate.Substring(0, reasonIndex).Trim();

                    if (candidate.Contains("\\"))
                        candidate = candidate.Substring(candidate.LastIndexOf('\\') + 1).Trim();

                    if (candidate.Contains("@"))
                        candidate = candidate.Split('@')[0].Trim();

                    if (IsValidUsername(candidate))
                        return candidate;
                }

                // Pattern 3 (broad fallback): any "DOMAIN\Username" occurrence in the message.
                // Last resort for unknown locale formats.
                var domainMatch = Regex.Match(message, @"[A-Za-z0-9_\-]+\\([A-Za-z0-9_\.\-]+)", RegexOptions.IgnoreCase);
                if (domainMatch.Success)
                {
                    string candidate = domainMatch.Groups[1].Value.Trim();
                    if (IsValidUsername(candidate))
                    {
                        EventLog.WriteEntry("Application",
                            $"[DBG-1074] GetUserFromSystem1074Message: patterns 1+2 missed, broad fallback matched '{candidate}'",
                            EventLogEntryType.Information, 2020);
                        return candidate;
                    }
                }
            }
            catch (Exception ex)
            {
                EventLog.WriteEntry("Application",
                    $"[DBG-1074] GetUserFromSystem1074Message exception: {ex.Message}",
                    EventLogEntryType.Warning, 2021);
            }

            return null;
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

        /// <summary>
        /// Tries to find a 1074 event within 60 seconds before the given 6006 event time.
        /// Returns (username, shutdownType) if a matching 1074 exists, or (null, null) if not.
        /// shutdownType will be null if the paired 1074 was a Restart (not a real power-off).
        /// </summary>
        private (string? Username, string? ShutdownType) TryResolve1074StateFor6006(DateTime eventTime)
        {
            lock (last1074Lock)
            {
                if (string.IsNullOrWhiteSpace(last1074Username))
                {
                    EventLog.WriteEntry("Application",
                        $"[DBG-6006] TryResolve: no prior 1074 state in memory.",
                        EventLogEntryType.Information, 2010);
                    return (null, null);
                }

                double diffSeconds = Math.Abs((eventTime - last1074EventTime).TotalSeconds);
                // Windows shutdown: 6006 is usually within a few seconds of 1074,
                // but slow shutdowns (pending app close, etc.) can take up to 60s.
                if (diffSeconds > 60)
                {
                    EventLog.WriteEntry("Application",
                        $"[DBG-6006] TryResolve: diff={diffSeconds:F0}s exceeds 60s window. " +
                        $"last1074Time={last1074EventTime:O} 6006Time={eventTime:O}",
                        EventLogEntryType.Information, 2011);
                    return (null, null);
                }

                // If the paired 1074 was a Restart, we have a username but no confirmed shutdown type.
                // Return username but null shutdownType so caller knows this is unconfirmed.
                bool isRestart = IsRestartShutdownType(last1074ShutdownType);
                string? confirmedShutdownType = isRestart ? null : last1074ShutdownType;

                EventLog.WriteEntry("Application",
                    $"[DBG-6006] TryResolve: matched username='{last1074Username}' diff={diffSeconds:F1}s " +
                    $"1074Type='{last1074ShutdownType}' isRestart={isRestart}",
                    EventLogEntryType.Information, 2012);

                return (last1074Username, confirmedShutdownType);
            }
        }

        /// <summary>
        /// Returns true if the shutdown type string indicates a restart (not a power-off/shutdown).
        /// Case-insensitive.
        /// </summary>
        private static bool IsRestartShutdownType(string? shutdownType)
        {
            if (string.IsNullOrWhiteSpace(shutdownType))
                return false;

            return shutdownType.Contains("restart", StringComparison.OrdinalIgnoreCase) ||
                   shutdownType.Contains("reboot", StringComparison.OrdinalIgnoreCase);
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
