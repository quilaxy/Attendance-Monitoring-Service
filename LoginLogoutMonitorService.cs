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
        private Timer? checkpointHeartbeatTimer;
        private readonly object userLock = new object();
        private readonly object checkpointWriteLock = new object();
        private int activeDispatchCount = 0;
        private DateTime serviceStartTime;
        private volatile bool replayInProgress = false;
        private DateTime replayUpperBound = DateTime.MinValue;
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

        private readonly SummaryCache summaryCache =
            new SummaryCache(Path.Combine(DataDirectory, "summary-cache.json"));

        private static readonly TimeSpan MaxReplayLookback = TimeSpan.FromDays(7);

        /// <summary>
        /// Kalau false, hanya log essential (error, warning, lifecycle) yang ditulis.
        /// Log verbose (detail dispatch, debug system event, replay progress, dll) di-skip.
        /// Di-set dari AppSettings:VerboseLogging di appsettings.json. Default: false.
        /// </summary>
        public static bool VerboseLogging
        {
            get => _verboseLogging;
            set => _verboseLogging = value;
        }
        private static bool _verboseLogging = false;

        public LoginLogoutMonitorService()
        {
            // Allow OnShutdown() to be called during system shutdown/restart.
            // Without this, ServiceBase never invokes OnShutdown() and the checkpoint is lost.
            CanShutdown = true;

            // FIX [CRASH]: Tangkap unhandled exception sebelum process mati.
            // Tanpa ini, crash 0xe0434352 tidak ter-log sama sekali dan
            // event-stop.checkpoint tidak tersimpan sehingga window replay
            // berikutnya bisa salah (root cause event 4624 annafi hilang).
            AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;
            TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;

            EnsureCheckpointBootstrap();

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
                SafeWriteEventLog("Application",
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

                    serviceStartTime = DateTime.UtcNow;

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

                    // Make sure ProgramData checkpoint files exist even after abrupt previous crash.
                    EnsureCheckpointBootstrap();

                    // FIX [GAP]: Aktifkan listener SEBELUM replay dimulai.
                    //
                    // Masalah sebelumnya:
                    //   replayTo = DateTime.Now (di-capture sebelum listener aktif)
                    //   Replay jalan ~8 detik → listener baru aktif di MonitorEvents()
                    //   Event yang terjadi antara replayTo dan listener-aktif = HILANG
                    //   Inilah yang menyebabkan 4624 annafi (10:25:15) tidak masuk.
                    //
                    // Solusi:
                    //   EnableRaisingEvents = true SEBELUM ReplayMissedEventsFromCheckpoint().
                    //   Event yang masuk saat replay berlangsung akan di-dedup secara otomatis
                    //   oleh PersistentEventQueue.EnqueueIfNotDuplicateAsync() — tidak ada
                    //   risiko duplikasi.
                    if (securityEventLog != null)
                        securityEventLog.EnableRaisingEvents = true;
                    if (systemEventLog != null)
                        systemEventLog.EnableRaisingEvents = true;

                    // Replay any events missed while service was down
                    ReplayMissedEventsFromCheckpoint();

                    StartCheckpointHeartbeat();

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
                        SafeWriteEventLog("Application",
                            $"EmployeeLoginLogoutService failed to start after {maxRetries} attempts: {ex.Message}",
                            EventLogEntryType.Error, 1002);
                        return;
                    }
                    Thread.Sleep(2000);
                }
            }

            if (started)
            {
                SafeWriteEventLog("Attendance-Service",
                    "Service started successfully.",
                    EventLogEntryType.Information, 0);
            }
        }

        // ─── Crash handler ───────────────────────────────────────────────────────

        /// <summary>
        /// Dipanggil saat ada unhandled exception yang akan mematikan process.
        /// Tiga tujuan:
        ///   1. Log exception lengkap ke Application EventLog dan crash.log
        ///   2. Simpan event-stop.checkpoint agar replay window berikutnya benar
        ///   3. Tidak throw — handler ini tidak boleh crash sendiri
        /// </summary>
        private void OnUnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            try
            {
                string message = e.ExceptionObject?.ToString() ?? "(exception object null)";

                // 1. Tulis ke Application EventLog — terbaca di Event Viewer
                try
                {
                    SafeWriteEventLog("Application",
                        $"[CRASH] Unhandled exception (isTerminating={e.IsTerminating}):\n{message}",
                        EventLogEntryType.Error, 9999);
                }
                catch { /* EventLog mungkin sudah shutdown saat system restart */ }

                // 2. Append ke crash.log — terbaca tanpa akses Event Viewer
                try
                {
                    Directory.CreateDirectory(DataDirectory);
                    string crashLogPath = Path.Combine(DataDirectory, "crash.log");
                    string content = $"[{DateTime.Now:O}] isTerminating={e.IsTerminating}\n{message}\n\n";
                    File.AppendAllText(crashLogPath, content);
                }
                catch { /* DataDirectory mungkin belum tersedia */ }

                // 3. Simpan stop checkpoint agar replay window berikutnya benar.
                //    Tanpa ini, service restart berikutnya fallback ke replayCheckpoint-5min
                //    sehingga replayTo bisa terlambat dan event login bisa hilang lagi.
                try
                {
                    SaveStopCheckpoint(DateTime.UtcNow.AddMinutes(-1));
                }
                catch { /* last resort */ }
            }
            catch { /* absolute last resort — jangan sampai throw dari handler ini */ }
        }

        private void OnUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
        {
            try
            {
                SafeWriteEventLog("Application",
                    $"[CRASH] Unobserved task exception: {e.Exception}",
                    EventLogEntryType.Error, 9998);
                SaveStopCheckpoint(DateTime.UtcNow.AddMinutes(-1));
                e.SetObserved();
            }
            catch
            {
                // Never throw from global exception hooks.
            }
        }

        // ─── Replay missed events ────────────────────────────────────────────────

        private void ReplayMissedEventsFromCheckpoint()
        {
            DateTime replayTo = DateTime.UtcNow;
            replayUpperBound = replayTo;
            replayInProgress = true;

            try
            {
                DateTime? replayFrom = LoadStopCheckpoint();

                SafeWriteEventLog("Application",
                    $"ReplayMissedEvents: replayFrom={replayFrom?.ToString("O") ?? "(none)"} replayTo={replayTo:O}",
                    EventLogEntryType.Information, 1034);

                if (replayFrom.HasValue)
                {
                    // Security events first so lastActiveUser is populated before system events run.
                    ReplaySecurityEvents(replayFrom, replayTo);

                    // System events: extend replayFrom 30 detik lebih awal agar 1074 yang terjadi
                    // tepat sebelum checkpoint window tetap ter-load ke memory sebelum 6006 di-replay.
                    // Tanpa ini, 1074 di detik terakhir sebelum replayFrom ter-potong → 6006 unconfirmed.
                    // DedupWindow 30 detik akan tangkap duplikat kalau 1074 sudah ada di queue.
                    DateTime systemReplayFrom = replayFrom.Value.AddSeconds(-30);
                    ReplaySystemEvents(systemReplayFrom, replayTo);
                }
                else
                {
                    SafeWriteEventLog("Application",
                        "ReplayMissedEvents: no checkpoint found, skipping replay.",
                        EventLogEntryType.Information, 1029);
                }

                SaveReplayCheckpoint(replayTo);
            }
            catch (Exception ex)
            {
                SafeWriteEventLog("Application",
                    $"Error while replaying startup events: {ex.Message}",
                    EventLogEntryType.Warning, 1014);
            }
            finally
            {
                replayInProgress = false;
            }
        }

        private DateTime? LoadStopCheckpoint()
        {
            try
            {
                // Level 1 – Primary checkpoint
                DateTime? checkpoint = TryLoadCheckpoint(stopCheckpointPath);
                if (checkpoint.HasValue)
                {
                    SafeWriteEventLog("Application",
                        $"LoadStopCheckpoint: loaded from primary '{stopCheckpointPath}' → {checkpoint.Value:O}",
                        EventLogEntryType.Information, 1024);
                    return checkpoint;
                }

                SafeWriteEventLog("Application",
                    $"LoadStopCheckpoint: primary not found at '{stopCheckpointPath}', trying backup.",
                    EventLogEntryType.Warning, 1023);

                // Level 2 – Backup checkpoint (in case primary write was interrupted mid-shutdown)
                checkpoint = TryLoadCheckpoint(stopCheckpointBackupPath);
                if (checkpoint.HasValue)
                {
                    SafeWriteEventLog("Application",
                        $"LoadStopCheckpoint: loaded from backup '{stopCheckpointBackupPath}' → {checkpoint.Value:O}",
                        EventLogEntryType.Warning, 1023);
                    return checkpoint;
                }

                // Level 3 – Derive from replay checkpoint -5 min so we don't miss events
                // written right before the previous service start.
                // If derived timestamp is older than MaxReplayLookback (7 days), clamp to
                // exactly 7 days back — never fall back to an arbitrary short window so that
                // long weekends, public holidays, and extended leave are always covered.
                DateTime now = DateTime.UtcNow;
                DateTime? replayCheckpoint = TryLoadCheckpoint(replayCheckpointPath);
                if (replayCheckpoint.HasValue)
                {
                    DateTime derived = replayCheckpoint.Value.AddMinutes(-5);
                    DateTime maxLookback = now - MaxReplayLookback;

                    if (derived < maxLookback)
                    {
                        // Replay checkpoint is stale (e.g. leftover from a reinstall).
                        // Clamp to MaxReplayLookback so we still cover up to 7 days,
                        // rather than collapsing to a tiny 10-minute window.
                        SafeWriteEventLog("Application",
                            $"LoadStopCheckpoint: replay checkpoint stale ({replayCheckpoint.Value:O}); " +
                            $"clamping replayFrom to MaxReplayLookback boundary {maxLookback:O} " +
                            $"instead of derived {derived:O}",
                            EventLogEntryType.Warning, 1043);
                        return maxLookback;
                    }

                    SafeWriteEventLog("Application",
                        $"LoadStopCheckpoint: both stop checkpoints missing — deriving from replay checkpoint " +
                        $"({replayCheckpoint.Value:O}) -5min → {derived:O}",
                        EventLogEntryType.Warning, 1023);
                    return derived;
                }

                // Level 4 – Fresh install seed.
                // Tidak ada checkpoint sama sekali (primary, backup, replay) — ini fresh install
                // atau DataDirectory baru dibersihkan. Replay dari 00:00 hari ini (UTC) agar event
                // login pagi (sebelum service pertama kali distart) ikut masuk.
                // Tidak replay lebih jauh agar tidak flood Security log historical.
                DateTime todayMidnightUtc = now.Date; // UTC midnight
                SafeWriteEventLog("Application",
                    $"LoadStopCheckpoint: FRESH INSTALL — no checkpoint found anywhere. " +
                    $"Seeding replayFrom to today midnight {todayMidnightUtc:O} " +
                    $"so events from 00:00 today are captured.",
                    EventLogEntryType.Warning, 1023);
                return todayMidnightUtc;
            }
            catch (Exception ex)
            {
                SafeWriteEventLog("Application",
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

            // Checkpoint disimpan sebagai UTC (Z suffix) — return as UTC.
            return parsed.Kind == DateTimeKind.Utc ? parsed : parsed.ToUniversalTime();
        }

        private void EnsureCheckpointBootstrap()
        {
            try
            {
                // Hanya pastikan direktori ada — tidak seed checkpoint file.
                // LoadStopCheckpoint() adalah single source of truth untuk semua fallback,
                // termasuk fresh install (Level 4 → today 00:00).
                // Dulu Bootstrap meng-seed Now-1menit sehingga Level 4 tidak pernah tercapai
                // dan event login sebelum service start (misal 07:21) ikut terlewat.
                Directory.CreateDirectory(DataDirectory);

                SafeWriteEventLog("Application",
                    $"EnsureCheckpointBootstrap: DataDirectory ensured at '{DataDirectory}'",
                    EventLogEntryType.Information, 1025);
            }
            catch (Exception ex)
            {
                SafeWriteEventLog("Application",
                    $"EnsureCheckpointBootstrap failed: {ex.GetType().Name}: {ex.Message}",
                    EventLogEntryType.Warning, 1026);
            }
        }

        private void SaveStopCheckpoint(DateTime checkpoint)
        {
            try
            {
                lock (checkpointWriteLock)
                {
                    string? dir = Path.GetDirectoryName(stopCheckpointPath);

                    SafeWriteEventLog("Application",
                        $"SaveStopCheckpoint: dir='{dir}' path='{stopCheckpointPath}'",
                        EventLogEntryType.Information, 1020);

                    if (!string.IsNullOrWhiteSpace(dir) && !Directory.Exists(dir))
                    {
                        Directory.CreateDirectory(dir);
                        SafeWriteEventLog("Application",
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

                    SafeWriteEventLog("Application",
                        $"SaveStopCheckpoint: written '{content}' to primary + backup.",
                        EventLogEntryType.Information, 1022);
                }
            }
            catch (Exception ex)
            {
                SafeWriteEventLog("Application",
                    $"Failed to save stop checkpoint: {ex.GetType().Name}: {ex.Message} | Path='{stopCheckpointPath}'",
                    EventLogEntryType.Warning, 1017);
            }
        }

        private void StartCheckpointHeartbeat()
        {
            checkpointHeartbeatTimer?.Dispose();
            checkpointHeartbeatTimer = new Timer(_ =>
            {
                try
                {
                    // Heartbeat menulis Now tanpa pengurangan — per-event sudah handle
                    // akurasi (eventTime - 1 detik). Heartbeat hanya safety net saat idle.
                    // Interval 1 menit cukup: worst-case gap = 59 detik, di-cover replay 7 hari.
                    SaveStopCheckpoint(DateTime.UtcNow);
                }
                catch
                {
                    // Heartbeat must never crash service.
                }
            }, null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));
        }

        private static void SafeWriteEventLog(string source, string message, EventLogEntryType type, int eventId)
        {
            // Kalau VerboseLogging=false, skip event ID yang masuk kategori verbose.
            // Hanya error, warning essential, dan lifecycle event yang tetap ditulis.
            if (!_verboseLogging && _verboseOnlyEventIds.Contains(eventId))
                return;

            try
            {
                EventLog.WriteEntry(source, message, type, eventId);
            }
            catch
            {
                // Ignore EventLog failures during shutdown windows.
            }
        }

        /// <summary>
        /// Event ID yang hanya ditulis saat VerboseLogging=true.
        /// Di production, log ini terlalu banyak dan tidak diperlukan untuk monitoring normal.
        /// </summary>
        private static readonly HashSet<int> _verboseOnlyEventIds = new HashSet<int>
        {
            // Checkpoint detail
            1018, 1019, 1020, 1021, 1022, 1025,
            // Replay progress
            1030, 1031, 1032, 1033, 1034,
            // Live event skip & duplicate skip — normal behavior, bukan error
            1016, 1037, 1038,
            // Debug system event parsing — semua [DBG-*]
            2001, 2002, 2003, 2004, 2005, 2006, 2007, 2010, 2011, 2012, 2020, 2021,
            // SharePoint summary detail
            3001, 3002, 3003, 3004, 3005, 3007, 3008,
            3010, 3011, 3012, 3013, 3014, 3015, 3016, 3017, 3018, 3021, 3022,
            // Dispatch detail
            4002, 4003, 4004, 4005, 4008, 4009, 4010,
            // RAW insert success detail
            4020, 4021, 4022, 4025,
            // Cleanup progress detail
            5001, 5002, 5003, 5006,
        };

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
                SafeWriteEventLog("Application",
                    "ReplaySecurityEvents: fromTime is null — skipping to avoid full log flood.",
                    EventLogEntryType.Warning, 1035);
                return;
            }

            // Collect and sort ascending (oldest-first) for consistent ordering.
            var entries = new List<(DateTime Time, EventLogEntry Entry, int EventId)>();

            for (int i = securityEventLog.Entries.Count - 1; i >= 0; i--)
            {
                EventLogEntry entry = securityEventLog.Entries[i];
                DateTime eventTime = entry.TimeGenerated.ToUniversalTime();

                if (eventTime < fromTime.Value)
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

            SafeWriteEventLog("Application",
                $"ReplaySecurityEvents: found {entries.Count} security events between {fromTime:O} and {toTime:O}.",
                EventLogEntryType.Information, 1032);

            entries.Sort((a, b) => a.Time.CompareTo(b.Time));

            foreach (var (time, entry, eventId) in entries)
            {
                SafeWriteEventLog("Application",
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
                SafeWriteEventLog("Application",
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
                DateTime eventTime = entry.TimeGenerated.ToUniversalTime();

                if (eventTime < fromTime.Value)  // fromTime non-null guaranteed by guard above
                    continue;

                if (eventTime > toTime)
                    continue;

                int eventId = GetNormalizedEventId(entry);
                if (eventId != 1074 && eventId != 6006 && eventId != 6008 && eventId != 41 && eventId != 42)
                    continue;

                entries.Add((eventTime, entry, eventId));
            }

            SafeWriteEventLog("Application",
                $"ReplaySystemEvents: found {entries.Count} system events between {fromTime:O} and {toTime:O}.",
                EventLogEntryType.Information, 1030);

            // Sort oldest-first so 1074 is always processed before its paired 6006
            entries.Sort((a, b) => a.Time.CompareTo(b.Time));

            foreach (var (time, entry, eventId) in entries)
            {
                SafeWriteEventLog("Application",
                    $"ReplaySystemEvents: processing EventId={eventId} at {time:O} Source={entry.Source}",
                    EventLogEntryType.Information, 1031);

                ProcessSystemEntryAsync(entry, writeRawRecord: true).GetAwaiter().GetResult();
            }
        }

        // ─── Configuration ───────────────────────────────────────────────────────

        private IConfiguration LoadConfiguration(string baseDirectory)
        {
            string plainConfigPath = Path.Combine(baseDirectory, "appsettings.json");
            IConfiguration config;

            if (File.Exists(plainConfigPath))
            {
                config = new ConfigurationBuilder()
                    .SetBasePath(baseDirectory)
                    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: false)
                    .Build();
            }
            else
            {
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
                    config = configBuilder.Build();
                }
                catch (Exception ex)
                {
                    SafeWriteEventLog("Application",
                        $"Failed to decrypt configuration: {ex.Message}",
                        EventLogEntryType.Error, 1004);
                    throw;
                }
            }

            // Baca VerboseLogging dari AppSettings — default false (production mode)
            VerboseLogging = config.GetValue<bool>("AppSettings:VerboseLogging", defaultValue: false);

            return config;
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
                // Hanya tulis kalau kandidat lebih baru dari checkpoint yang sudah ada —
                // jangan mundurkan checkpoint yang sudah akurat dari per-event atau heartbeat.
                // Now - 5 detik sebagai buffer kecil agar event yang sedang in-flight tidak terpotong.
                DateTime candidate = DateTime.UtcNow.AddSeconds(-5);
                DateTime? existing = TryLoadCheckpoint(stopCheckpointPath);
                DateTime stopCheckpoint = (existing.HasValue && existing.Value > candidate)
                    ? existing.Value
                    : candidate;

                SafeWriteEventLog("Application",
                    $"{caller}: saving checkpoint {stopCheckpoint:O} " +
                    $"(candidate={candidate:O} existing={existing?.ToString("O") ?? "(none)"})",
                    EventLogEntryType.Information, 1018);

                SaveStopCheckpoint(stopCheckpoint);

                SafeWriteEventLog("Application",
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

                checkpointHeartbeatTimer?.Dispose();
                checkpointHeartbeatTimer = null;

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

                SafeWriteEventLog("Attendance-Service",
                    $"Service has been successfully shut down ({caller}).",
                    EventLogEntryType.Information, 0);
            }
            catch (Exception ex)
            {
                SafeWriteEventLog("Application",
                    $"Error in {caller}: {ex.Message}",
                    EventLogEntryType.Warning, 1006);
            }
        }

        // ─── Monitor loop ────────────────────────────────────────────────────────

        private void MonitorEvents(CancellationToken cancellationToken)
        {
            try
            {
                // FIX [GAP]: EnableRaisingEvents sudah diaktifkan di OnStart() sebelum replay
                // dimulai. Tidak perlu diaktifkan lagi di sini untuk menghindari double-enable.
                // HandleServiceStopping() masih meng-disable dengan benar saat service berhenti.

                Task.Run(() => CleanupOldRecordsTask(cancellationToken), cancellationToken);
                Task.Run(() => ProcessQueuedEventsTask(cancellationToken), cancellationToken);

                while (!cancellationToken.IsCancellationRequested)
                    Thread.Sleep(5000);
            }
            catch (Exception ex)
            {
                SafeWriteEventLog("Application",
                    $"Error in MonitorEvents: {ex.Message}",
                    EventLogEntryType.Error, 1007);
            }
        }

        // ─── Queue processor ─────────────────────────────────────────────────────

        private async Task ProcessQueuedEventsTask(CancellationToken cancellationToken)
        {
            var retryCount = new Dictionary<string, int>();

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
                        retryCount.Remove(next.QueueId);
                        await eventQueue.RemoveByIdAsync(next.QueueId, cancellationToken);
                        continue;
                    }

                    // Kalau gagal, increment retry counter in-memory.
                    // Setelah 5x gagal, skip summary agar queue tidak stuck.
                    retryCount.TryGetValue(next.QueueId, out int count);
                    retryCount[next.QueueId] = ++count;

                    if (count >= 5 &&
                        (!next.WriteRawRecord || next.RawRecordDispatched) &&
                        ShouldProcessSummary(next) && !next.SummaryDispatched)
                    {
                        SafeWriteEventLog("Application",
                            $"[DISPATCH] Summary permanently failed after {count} attempts — " +
                            $"skipping summary for queueId={next.QueueId} eventId={next.EventId} user={next.Username}",
                            EventLogEntryType.Warning, 1029);
                        retryCount.Remove(next.QueueId);
                        await eventQueue.UpdateDispatchStateAsync(next.QueueId, summaryDispatched: true);
                        await eventQueue.RemoveByIdAsync(next.QueueId, cancellationToken);
                        continue;
                    }

                    await Task.Delay(TimeSpan.FromSeconds(10), cancellationToken);
                }
                catch (TaskCanceledException) { break; }
                catch (Exception ex)
                {
                    SafeWriteEventLog("Application",
                        $"Error in ProcessQueuedEventsTask: {ex.Message}",
                        EventLogEntryType.Warning, 1015);
                    try { await Task.Delay(TimeSpan.FromSeconds(15), cancellationToken); }
                    catch (TaskCanceledException) { break; }
                }
            }
        }

        private static bool ShouldProcessSummary(QueuedAttendanceEvent item)
        {
            // 4624: hanya proses summary kalau ini first login of day (IsSummaryEligible).
            if (item.EventId == 4624)
                return item.IsSummaryEligible;

            // Seluruh group ditandai restart → semua member skip summary.
            // Ini mencakup 4647, 1074, dan 6006 dalam rangkaian restart.
            if (item.ShutdownGroupIsRestart)
                return false;

            // 1074 Restart: skip — bukan shutdown, tidak perlu tulis ShutdownTime.
            if (item.EventId == 1074 &&
                (item.EventType.Contains("Restart", StringComparison.OrdinalIgnoreCase) ||
                 item.EventType.Contains("Reboot", StringComparison.OrdinalIgnoreCase)))
                return false;

            // 6006 Unconfirmed: tidak ada paired 1074 shutdown → kemungkinan restart → skip.
            if (item.EventId == 6006 &&
                item.EventType.Contains("unconfirmed", StringComparison.OrdinalIgnoreCase))
                return false;

            return item.EventId == 1074 || item.EventId == 6006 ||
                   item.EventId == 4647 || item.EventId == 6008 || item.EventId == 41;
        }

        /// <summary>
        /// Priority untuk shutdown group — harus konsisten dengan SharePointIntegration.GetShutdownPriority.
        /// Dipakai untuk menentukan event mana di group yang boleh dispatch summary saat timer expired.
        /// </summary>
        private static int GetShutdownEventPriority(int eventId, string eventType)
        {
            if (eventId == 6006)
                return eventType.Contains("unconfirmed", StringComparison.OrdinalIgnoreCase) ? 0 : 5;
            if (eventId == 1074 && !eventType.Contains("restart", StringComparison.OrdinalIgnoreCase)
                                && !eventType.Contains("reboot", StringComparison.OrdinalIgnoreCase)) return 4;
            if (eventId == 4647) return 2;
            if (eventId == 6008) return 1;
            if (eventId == 41)   return 1;
            return 0;
        }

        private async Task<bool> TryDispatchQueuedEventAsync(QueuedAttendanceEvent item)
        {
            try
            {
                var sharePoint = sharePointIntegration.Value;
                string? accessToken = await sharePoint.GetAccessTokenAsync(item.EventTime, item.EventId);
                if (string.IsNullOrEmpty(accessToken))
                {
                    SafeWriteEventLog("Application",
                        $"[DISPATCH] Token null — skipping queueId={item.QueueId} eventId={item.EventId} user={item.Username}",
                        EventLogEntryType.Warning, 4001);
                    return false;
                }

                bool needsRaw     = item.WriteRawRecord && !item.RawRecordDispatched;
                bool needsSummary = ShouldProcessSummary(item) && !item.SummaryDispatched;

                // Shutdown group hold: tahan summary dispatch untuk 4647/1074/6006 sampai
                // group lengkap (ada 6006) atau timer 10 detik habis.
                // Raw tetap dispatch langsung — group hanya berlaku untuk summary.
                if (needsSummary && item.ShutdownGroupId != null && item.ShutdownGroupHoldUntil.HasValue)
                {
                    bool timerExpired = DateTime.UtcNow >= item.ShutdownGroupHoldUntil.Value;
                    bool has6006InGroup = await eventQueue.GroupHas6006Async(item.ShutdownGroupId);
                    bool isThis6006 = item.EventId == 6006;

                    if (!timerExpired && !has6006InGroup && !isThis6006)
                    {
                        // Group belum lengkap dan timer belum habis — tahan summary, proses raw dulu
                        needsSummary = false;
                        SafeWriteEventLog("Application",
                            $"[DISPATCH] Shutdown group hold: waiting for 6006 or timer. " +
                            $"queueId={item.QueueId} eventId={item.EventId} groupId={item.ShutdownGroupId} " +
                            $"holdUntil={item.ShutdownGroupHoldUntil.Value:O}",
                            EventLogEntryType.Information, 4008);
                    }
                    else if (!isThis6006 && has6006InGroup)
                    {
                        // 6006 sudah ada di group — event ini (4647/1074) tidak perlu kirim summary,
                        // biarkan 6006 yang kirim dengan priority tertinggi.
                        needsSummary = false;
                        SafeWriteEventLog("Application",
                            $"[DISPATCH] Shutdown group: 6006 already in group, skipping summary for " +
                            $"queueId={item.QueueId} eventId={item.EventId}",
                            EventLogEntryType.Information, 4009);
                        await eventQueue.UpdateDispatchStateAsync(item.QueueId, summaryDispatched: true);
                        item.SummaryDispatched = true;
                    }
                    else if (timerExpired && !has6006InGroup && !isThis6006)
                    {
                        // Timer expired, 6006 tidak muncul (misal Fast Startup).
                        // Hanya event dengan priority tertinggi di group yang boleh kirim summary.
                        // Cek apakah ada event lain di group yang priority-nya lebih tinggi.
                        int myPriority = GetShutdownEventPriority(item.EventId, item.EventType);
                        bool higherPriorityExistsInGroup = await eventQueue.GroupHasHigherPriorityAsync(
                            item.ShutdownGroupId, myPriority);

                        if (higherPriorityExistsInGroup)
                        {
                            // Ada yang lebih tinggi — skip summary untuk event ini
                            needsSummary = false;
                            SafeWriteEventLog("Application",
                                $"[DISPATCH] Shutdown group: timer expired, higher priority exists, skipping summary for " +
                                $"queueId={item.QueueId} eventId={item.EventId} priority={myPriority}",
                                EventLogEntryType.Information, 4009);
                            await eventQueue.UpdateDispatchStateAsync(item.QueueId, summaryDispatched: true);
                            item.SummaryDispatched = true;
                        }
                        // else: ini yang tertinggi → kirim summary
                    }
                    // else: isThis6006=true → kirim summary dengan priority 5
                }

                SafeWriteEventLog("Application",
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
                    SafeWriteEventLog("Application",
                        $"[DISPATCH] Raw record sent: queueId={item.QueueId} eventId={item.EventId} user={item.Username}",
                        EventLogEntryType.Information, 4003);
                }

                if (needsSummary)
                {
                    if (item.EventId == 4624)
                    {
                        SafeWriteEventLog("Application",
                            $"[DISPATCH] Sending summary login: user={item.Username} computer={item.ComputerName} " +
                            $"loginTime={item.LoginTime?.ToString("O") ?? item.EventTime.ToString("O")}",
                            EventLogEntryType.Information, 4004);

                        await sharePoint.UpsertDailySummaryLoginAsync(
                            accessToken, item.Username, item.ComputerName,
                            item.LoginTime ?? item.EventTime, summaryCache);
                    }
                    else
                    {
                        SafeWriteEventLog("Application",
                            $"[DISPATCH] Sending summary shutdown: user={item.Username} computer={item.ComputerName} " +
                            $"shutdownTime={item.ShutdownTime?.ToString("O") ?? item.EventTime.ToString("O")} " +
                            $"eventId={item.EventId} eventType='{item.EventType}'",
                            EventLogEntryType.Information, 4005);

                        await sharePoint.TryUpdateDailySummaryShutdownAsync(
                            accessToken, item.Username, item.ComputerName,
                            item.ShutdownTime ?? item.EventTime,
                            item.EventId, item.EventType, summaryCache);
                    }

                    await eventQueue.UpdateDispatchStateAsync(item.QueueId, summaryDispatched: true);
                    item.SummaryDispatched = true;
                    SafeWriteEventLog("Application",
                        $"[DISPATCH] Summary dispatched: queueId={item.QueueId} eventId={item.EventId} user={item.Username}",
                        EventLogEntryType.Information, 4006);

                    // Kalau ini adalah event dari shutdown group, mark semua member lain
                    // sebagai summaryDispatched=true agar mereka tidak ikut kirim summary.
                    // Ini penting untuk kasus timer expired tanpa 6006 — setelah 1074 kirim
                    // summary, 4647 yang masih di queue tidak boleh kirim lagi.
                    if (item.ShutdownGroupId != null)
                        await eventQueue.MarkGroupSummaryDispatchedAsync(item.ShutdownGroupId, exceptQueueId: item.QueueId);
                }

                bool doneRaw     = !item.WriteRawRecord || item.RawRecordDispatched;
                bool doneSummary = !ShouldProcessSummary(item) || item.SummaryDispatched;

                SafeWriteEventLog("Application",
                    $"[DISPATCH] Done: queueId={item.QueueId} doneRaw={doneRaw} doneSummary={doneSummary}",
                    EventLogEntryType.Information, 4007);

                return doneRaw && doneSummary;
            }
            catch (Exception ex)
            {
                SafeWriteEventLog("Application",
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
                        await summaryCache.CleanupOldEntriesAsync(cancellationToken);
                    }

                    await Task.Delay(nextRun - DateTime.Now, cancellationToken);

                    int scheduledDelay = new Random(Environment.MachineName.GetHashCode()).Next(0, 300000);
                    await Task.Delay(scheduledDelay, cancellationToken);
                    await sharePointIntegration.Value.CleanupOldRecordsAsync(retentionMonths);
                    await summaryCache.CleanupOldEntriesAsync(cancellationToken);
                }
                catch (TaskCanceledException) { break; }
                catch (Exception ex)
                {
                    SafeWriteEventLog("Application",
                        $"Error in CleanupOldRecordsTask: {ex.Message}",
                        EventLogEntryType.Warning, 1008);
                    try { await Task.Delay(TimeSpan.FromHours(1), cancellationToken); }
                    catch (TaskCanceledException) { break; }
                }
            }
        }

        // ─── Event handlers ──────────────────────────────────────────────────────

        private void OnSecurityEventWritten(object sender, EntryWrittenEventArgs e)
        {
            if (e?.Entry == null) return;

            EventLogEntry entry = e.Entry;
            if (ShouldSkipLiveEntry(entry.TimeGenerated.ToUniversalTime()))
                return;

            _ = Task.Run(async () =>
            {
                try
                {
                    await ProcessSecurityEntryAsync(entry, writeRawRecord: true);
                }
                catch (Exception ex)
                {
                    SafeWriteEventLog("Application",
                        $"Unhandled exception in OnSecurityEventWritten: {ex}",
                        EventLogEntryType.Error, 9997);
                    SaveStopCheckpoint(DateTime.UtcNow.AddMinutes(-1));
                }
            });
        }

        private DateTime _lastSkipLogTime = DateTime.MinValue;
        private int _skipLogSuppressedCount = 0;

        private bool ShouldSkipLiveEntry(DateTime eventTime)
        {
            if (eventTime <= replayUpperBound)
            {
                if (replayInProgress)
                {
                    SafeWriteEventLog("Application",
                        $"Live event skipped during replay overlap: eventTime={eventTime:O} replayUpperBound={replayUpperBound:O}",
                        EventLogEntryType.Information, 1037);
                }
                else
                {
                    // Rate-limit log 1038 — maksimal 1x per 30 detik, sisanya di-suppress
                    bool shouldLog = (DateTime.Now - _lastSkipLogTime).TotalSeconds >= 30;
                    if (shouldLog)
                    {
                        string suffix = _skipLogSuppressedCount > 0
                            ? $" (+ {_skipLogSuppressedCount} suppressed)"
                            : string.Empty;
                        SafeWriteEventLog("Application",
                            $"Live event skipped — older than replayUpperBound: eventTime={eventTime:O} replayUpperBound={replayUpperBound:O}{suffix}",
                            EventLogEntryType.Information, 1038);
                        _lastSkipLogTime = DateTime.Now;
                        _skipLogSuppressedCount = 0;
                    }
                    else
                    {
                        _skipLogSuppressedCount++;
                    }
                }
                return true;
            }

            return false;
        }

        private async Task ProcessSecurityEntryAsync(EventLogEntry log, bool writeRawRecord)
        {
            try
            {
                int eventId = GetNormalizedEventId(log);
                if (eventId != 4624 && eventId != 4647) return;

                DateTime eventTime = log.TimeGenerated.ToUniversalTime();
                string computerName = log.MachineName;
                string eventMessage = log.Message;

                // Parse logon type (only relevant for 4624)
                int logonType = 0;
                if (eventId == 4624)
                    logonType = ParseLogonType(eventMessage);

                if (eventId == 4624 && !IsRelevantLogonType(logonType))
                    return;

                // Skip admin (UAC split token) logins.
                // Windows membuat 2 event 4624 untuk admin login:
                //   - Elevated Token: Yes  (high integrity token)
                //   - Elevated Token: No   (filtered standard token)
                // Keduanya punya Linked Logon ID non-zero yang saling pointing.
                // Kalau Linked Logon ID != 0x0 → ini bagian dari admin split token → skip.
                if (eventId == 4624 && IsAdminSplitTokenLogin(eventMessage))
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
                SafeWriteEventLog("Application",
                    $"Error in ProcessSecurityEntryAsync: {ex.Message}",
                    EventLogEntryType.Warning, 1009);
            }
        }

        private void OnSystemEventWritten(object sender, EntryWrittenEventArgs e)
        {
            if (e?.Entry == null) return;

            EventLogEntry entry = e.Entry;
            if (ShouldSkipLiveEntry(entry.TimeGenerated.ToUniversalTime()))
                return;

            _ = Task.Run(async () =>
            {
                try
                {
                    await ProcessSystemEntryAsync(entry, writeRawRecord: true);
                }
                catch (Exception ex)
                {
                    SafeWriteEventLog("Application",
                        $"Unhandled exception in OnSystemEventWritten: {ex}",
                        EventLogEntryType.Error, 9996);
                    SaveStopCheckpoint(DateTime.UtcNow.AddMinutes(-1));
                }
            });
        }

        private async Task ProcessSystemEntryAsync(EventLogEntry log, bool writeRawRecord)
        {
            try
            {
                int eventId = GetNormalizedEventId(log);
                if (eventId != 1074 && eventId != 6006 && eventId != 6008 && eventId != 41 && eventId != 42)
                    return;

                DateTime eventTime = log.TimeGenerated.ToUniversalTime();
                string computerName = log.MachineName;

                // ── 1074: Null-message guard + message preview for debugging ────────
                if (eventId == 1074)
                {
                    if (log.Message == null)
                    {
                        SafeWriteEventLog("Application",
                            $"[DBG-1074] EventId=1074 at {eventTime:O} has NULL message — skipping.",
                            EventLogEntryType.Warning, 2001);
                        return;
                    }

                    // Log first 300 chars of message so we can verify regex match
                    string preview = log.Message.Length > 300 ? log.Message.Substring(0, 300) : log.Message;
                    SafeWriteEventLog("Application",
                        $"[DBG-1074] at {eventTime:O} | MessagePreview: {preview}",
                        EventLogEntryType.Information, 2002);
                }

                string? eventMessage = (eventId == 1074) ? log.Message : null;
                string? username = (eventId == 1074) ? GetUserFromSystem1074Message(eventMessage) : null;

                if (eventId == 1074)
                {
                    SafeWriteEventLog("Application",
                        $"[DBG-1074] GetUserFromSystem1074Message returned: '{username ?? "(null)"}'",
                        EventLogEntryType.Information, 2003);
                }

                if (eventId == 1074 && !string.IsNullOrEmpty(username))
                {
                    string shutdownType = ParseShutdownType(eventMessage);
                    StoreLast1074State(username, eventTime, shutdownType);
                    SafeWriteEventLog("Application",
                        $"[DBG-1074] Stored state: Username={username} ShutdownType={shutdownType} Time={eventTime:O}",
                        EventLogEntryType.Information, 2004);
                }

                if (eventId == 6006)
                {
                    var (resolved, confirmed1074ShutdownType) = TryResolve1074StateFor6006(eventTime);
                    SafeWriteEventLog("Application",
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

                    SafeWriteEventLog("Application",
                        $"[DBG-{eventId}] username null after event parse, lastActiveUser='{fromLock ?? "(empty)"}'",
                        EventLogEntryType.Information, 2006);

                    username = fromLock;
                }

                if (string.IsNullOrEmpty(username))
                {
                    string? fromLog = GetMostRecentUser(eventTime);
                    SafeWriteEventLog("Application",
                        $"[DBG-{eventId}] username still null, GetMostRecentUser returned: '{fromLog ?? "(null)"}'",
                        EventLogEntryType.Information, 2007);

                    username = fromLog;
                    if (string.IsNullOrEmpty(username))
                    {
                        SafeWriteEventLog("Application",
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
                SafeWriteEventLog("Application",
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
                    QueueId         = Guid.NewGuid().ToString("N"),
                    EventId         = eventId,
                    Username        = username,
                    EventTime       = eventTime,
                    ComputerName    = computerName,
                    EventType       = eventType,
                    LogonType       = logonType,
                    LoginTime       = loginTime,
                    ExpectedTimeOut = expectedTimeOut,
                    ShutdownTime    = shutdownTime,
                    ShutdownType    = shutdownType,
                    WriteRawRecord  = writeRawRecord
                };

                // Shutdown group: 4647, 1074, 6006 yang terjadi berbarengan dikelompokkan
                // agar summary hanya di-dispatch setelah group lengkap (atau timeout 3 detik).
                // Tujuan: mencegah 4647 atau 1074 overwrite satu sama lain via isNewSession
                // padahal ketiganya satu rangkaian shutdown yang sama.
                // 6008 dan 41 tidak di-group karena mereka standalone (tidak ada paired event).
                if (eventId == 4647 || eventId == 1074 || eventId == 6006)
                {
                    string workDate = eventTime.ToLocalTime().ToString("yyyy-MM-dd");
                    // Group key: computer + user + tanggal + epoch menit (bukan detik) agar
                    // event dalam 60 detik yang sama masuk group yang sama.
                    long epochMinute = (long)(eventTime - DateTime.UnixEpoch).TotalMinutes;
                    queuedEvent.ShutdownGroupId = $"shutdown_{computerName}_{username}_{workDate}_{epochMinute}";
                    // Timer 3 detik — cukup untuk tunggu 1074/6006 yang fired hampir bersamaan,
                    // tapi tidak terlalu lama sampai network mati saat shutdown.
                    queuedEvent.ShutdownGroupHoldUntil = eventTime.AddSeconds(3);

                    // Kalau 1074 adalah restart, tandai seluruh group sebagai restart.
                    // Ini memastikan 4647 yang mungkin sudah masuk queue duluan juga ikut di-skip summary.
                    bool isRestartEvent = eventId == 1074 &&
                        (eventType.Contains("Restart", StringComparison.OrdinalIgnoreCase) ||
                         eventType.Contains("Reboot", StringComparison.OrdinalIgnoreCase));
                    if (isRestartEvent)
                        queuedEvent.ShutdownGroupIsRestart = true;
                }

                bool enqueued = await eventQueue.EnqueueIfNotDuplicateAsync(queuedEvent);

                // Propagate restart flag ke seluruh group setelah enqueue,
                // agar 4647 yang sudah ada di queue sebelum 1074 juga ter-mark.
                if (enqueued && queuedEvent.ShutdownGroupIsRestart && queuedEvent.ShutdownGroupId != null)
                    await eventQueue.MarkGroupAsRestartAsync(queuedEvent.ShutdownGroupId);

                if (!enqueued)
                {
                    SafeWriteEventLog("Application",
                        $"Duplicate event skipped: EventId={eventId} User={username} Time={eventTime:HH:mm:ss}",
                        EventLogEntryType.Information, 1016);
                }
                else
                {
                    // FIX [CRASH-0xe0434352]: Checkpoint per-event — tulis setiap kali event
                    // berhasil masuk queue. eventTime - 1 detik agar event ini ikut di-replay
                    // kalau service restart sebelum dispatch selesai.
                    //
                    // PENTING: hanya maju, tidak pernah mundur.
                    // Tanpa guard ini, replay event lama (misal dari 2 Maret) akan overwrite
                    // checkpoint hari ini (12 Maret) → restart berikutnya replay dari 2 Maret
                    // → semua data lama masuk lagi.
                    DateTime candidate = eventTime.AddSeconds(-1);
                    DateTime? existingCheckpoint = TryLoadCheckpoint(stopCheckpointPath);
                    if (!existingCheckpoint.HasValue || candidate > existingCheckpoint.Value)
                        SaveStopCheckpoint(candidate);
                }
            }
            catch (Exception ex)
            {
                SafeWriteEventLog("Application",
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
                        entry.TimeGenerated.ToUniversalTime() >= lookbackTime &&
                        entry.TimeGenerated.ToUniversalTime() <= beforeTime &&
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
        /// Deteksi admin login via UAC split token.
        /// Windows membuat 2 event 4624 untuk admin login — satu dengan Elevated Token: Yes
        /// (high integrity) dan satu dengan Elevated Token: No (filtered standard token).
        /// Keduanya punya Linked Logon ID non-zero yang saling pointing satu sama lain.
        ///
        /// Kalau Linked Logon ID != 0x0000000000000000 → ini bagian dari split token pair
        /// → skip kedua event, karena login admin tidak perlu di-record sebagai attendance.
        /// </summary>
        private static bool IsAdminSplitTokenLogin(string? message)
        {
            if (string.IsNullOrEmpty(message)) return false;
            try
            {
                var match = Regex.Match(message,
                    @"Linked Logon ID:\s*(0x[0-9A-Fa-f]+)",
                    RegexOptions.IgnoreCase);
                if (!match.Success) return false;

                string linkedId = match.Groups[1].Value.Trim();
                // 0x0 atau 0x0000000000000000 = tidak ada linked logon = bukan split token
                long parsed = Convert.ToInt64(linkedId, 16);
                return parsed != 0;
            }
            catch { return false; }
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
                        SafeWriteEventLog("Application",
                            $"[DBG-1074] GetUserFromSystem1074Message: patterns 1+2 missed, broad fallback matched '{candidate}'",
                            EventLogEntryType.Information, 2020);
                        return candidate;
                    }
                }
            }
            catch (Exception ex)
            {
                SafeWriteEventLog("Application",
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
                    SafeWriteEventLog("Application",
                        $"[DBG-6006] TryResolve: no prior 1074 state in memory.",
                        EventLogEntryType.Information, 2010);
                    return (null, null);
                }

                double diffSeconds = Math.Abs((eventTime - last1074EventTime).TotalSeconds);
                // Windows shutdown: 6006 is usually within a few seconds of 1074,
                // but slow shutdowns (pending app close, etc.) can take up to 60s.
                if (diffSeconds > 60)
                {
                    SafeWriteEventLog("Application",
                        $"[DBG-6006] TryResolve: diff={diffSeconds:F0}s exceeds 60s window. " +
                        $"last1074Time={last1074EventTime:O} 6006Time={eventTime:O}",
                        EventLogEntryType.Information, 2011);
                    return (null, null);
                }

                // If the paired 1074 was a Restart, we have a username but no confirmed shutdown type.
                // Return username but null shutdownType so caller knows this is unconfirmed.
                bool isRestart = IsRestartShutdownType(last1074ShutdownType);
                string? confirmedShutdownType = isRestart ? null : last1074ShutdownType;

                SafeWriteEventLog("Application",
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
