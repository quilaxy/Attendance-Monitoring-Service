using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Security.Principal;
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
        private readonly object sidCacheLock = new object();
        private readonly object checkpointWriteLock = new object();
        private readonly object knownLoginLock = new object();
        private readonly object firstLogonLock = new object();
        private readonly object startupAnchorLock = new object();
        private int activeDispatchCount = 0;
        private DateTime serviceStartTime;
        private volatile bool replayInProgress = false;
        private DateTime replayUpperBound = DateTime.MinValue;
        private readonly Lazy<SharePointIntegration> sharePointIntegration =
            new Lazy<SharePointIntegration>(() => new SharePointIntegration());

        // Shared 1074 state for resolving adjacent 6006 events.
        private static readonly object last1074Lock = new object();
        private static readonly List<Last1074State> last1074States = new List<Last1074State>();
        private static readonly TimeSpan primary1074PairWindow = TimeSpan.FromSeconds(60);
        private static readonly TimeSpan fallback1074PairWindow = TimeSpan.FromSeconds(120);
        private static readonly TimeSpan last1074RetentionWindow = TimeSpan.FromMinutes(5);
        private readonly Dictionary<string, string> sidUsernameCache =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, (string Username, DateTime EventTime)> lastKnownLoginByComputer =
            new Dictionary<string, (string Username, DateTime EventTime)>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, (string Username, DateTime EventTime)> firstLogon4624ByDeviceWorkDate =
            new Dictionary<string, (string Username, DateTime EventTime)>(StringComparer.OrdinalIgnoreCase);

        // Semua 4624 per computer per hari — dipakai untuk isNewSession check di shutdown dispatch.
        // Berbeda dari firstLogon4624ByDeviceWorkDate yang hanya simpan earliest login,
        // dictionary ini simpan semua login agar bisa detect sesi baru setelah shutdown pertama.
        private readonly Dictionary<string, List<DateTime>> allLogon4624ByDeviceWorkDate =
            new Dictionary<string, List<DateTime>>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, DateTime> startupAnchorByDeviceWorkDate =
            new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        private int queueAlertThreshold = 500;
        private TimeSpan startupToFirst4624MaxGapForDirectUse = TimeSpan.FromMinutes(90);
        private bool queueThresholdAlerted = false;
        private int[] dispatchBackoffSeconds = new[] { 30, 60, 120, 300, 600 };
        private HashSet<string> systemFallbackTriggerAccounts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "NT AUTHORITY\\SYSTEM",
            "NT AUTHORITY\\LOCAL SERVICE",
            "NT AUTHORITY\\NETWORK SERVICE"
        };
        private List<string> systemFallbackTriggerContains = new List<string>
        {
            "TrustedInstaller",
            "servicing",
            "SYSTEM",
            "LOCAL SERVICE",
            "NETWORK SERVICE"
        };

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
            new PersistentEventQueue(Path.Combine(DataDirectory, "queue"));

        private readonly SummaryCache summaryCache =
            new SummaryCache(Path.Combine(DataDirectory, "summary-cache.json"));

        // Opsi 3: simpan raw security event ke disk sebelum diproses,
        // sehingga kalau Security log ter-rotate/clear sebelum replay, data tidak hilang.
        private readonly RawEventStore rawEventStore =
            new RawEventStore(Path.Combine(DataDirectory, "rawevents"));

        private static readonly TimeSpan MaxReplayLookback = TimeSpan.FromDays(7);
        private static readonly TimeSpan PendingQueueRetention = TimeSpan.FromDays(7);

        private sealed class Last1074State
        {
            public Last1074State(string username, DateTime eventTime, string shutdownType)
            {
                Username = username;
                EventTime = eventTime;
                ShutdownType = shutdownType;
            }

            public string Username { get; }
            public DateTime EventTime { get; }
            public string ShutdownType { get; }
        }

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
            // #9: OnStart harus return dalam ~30 detik atau SCM kill service.
            // PrimeFirstLogon dan RetryPending cepat (in-memory + local disk).
            // ReplayMissedEvents bisa lama kalau checkpoint window besar (scan EventLog banyak entry).
            // Solusi: jalankan semua startup work di background thread, OnStart return segera
            // setelah setup dasar selesai. RequestAdditionalTime diperpanjang dari background.
            RequestAdditionalTime(30_000);

            // GAP FIX: Aktifkan listener SEBELUM apapun — sebelum init, sebelum replay.
            // Sebelumnya EnableRaisingEvents = true baru di-set setelah delay 10 detik (legacy
            // network wait) + PrimeFirstLogon + RetryPending selesai — ada gap ~12 detik di mana
            // 4624 yang masuk saat boot tidak tertangkap sama sekali.
            // Delay 10 detik juga sudah dihapus karena tidak perlu lagi — RawEventStore nulis
            // event ke disk real-time, network failure di-handle oleh retry queue.
            // Dengan dua fix ini, gap diperkecil dari ~12 detik menjadi <1 detik.
            if (securityEventLog != null)
                securityEventLog.EnableRaisingEvents = true;
            if (systemEventLog != null)
                systemEventLog.EnableRaisingEvents = true;

            int maxRetries = 5;
            int currentRetry = 0;
            bool started = false;

            while (currentRetry < maxRetries)
            {
                try
                {
                    currentRetry++;

                    serviceStartTime = DateTime.UtcNow;

                    SharePointIntegration.ResetNetworkWaitFlag();
                    SharePointIntegration.SetServiceStartTime(serviceStartTime);

                    // Delay awal dihapus — sebelumnya 10 detik untuk nunggu network ready,
                    // tapi sekarang tidak perlu karena:
                    // - RawEventStore sudah nulis event ke disk real-time (tidak bergantung network)
                    // - Kalau dispatch ke SharePoint gagal → masuk retry queue → otomatis retry
                    // - Delay justru memperbesar gap antara 4624 login dan service ready

                    string publishDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "");
                    Directory.SetCurrentDirectory(publishDirectory);

                    _ = LoadConfiguration(publishDirectory);

                    cancellationTokenSource = new CancellationTokenSource();
                    cancellationToken = cancellationTokenSource.Token;

                    EnsurCheckpointBootstrap();

                    // Startup background task — semua yang bisa lama dijalankan di sini
                    // agar OnStart bisa return dan SCM tidak timeout.
                    var ct = cancellationToken.Value;
                    Thread startupThread = new Thread(() =>
                    {
                        try
                        {
                            // Minta tambahan waktu dari background — SCM akan terus menunggu
                            // selama kita kirim RequestAdditionalTime sebelum deadline.
                            RequestAdditionalTime(120_000);

                            PrimeFirstLogonIndexFromQueueAsync(ct).GetAwaiter().GetResult();
                            RetryPendingQueueOnStartupAsync(ct).GetAwaiter().GetResult();

                            // EnableRaisingEvents sudah diaktifkan di OnStart() sebelum delay
                            // dan sebelum background thread ini jalan — tidak perlu set lagi di sini.

                            ReplayMissedEventsFromCheckpoint().GetAwaiter().GetResult();

                            StartCheckpointHeartbeat();

                            SafeWriteEventLog("Attendance-Service",
                                $"Service ready: replay complete, dispatch running. " +
                                $"Pending queue: {eventQueue.GetCountAsync().GetAwaiter().GetResult()} item(s).",
                                EventLogEntryType.Information, 1048);

                            // MonitorEvents loop (cleanup + dispatch tasks)
                            MonitorEvents(ct);
                        }
                        catch (Exception ex)
                        {
                            SafeWriteEventLog("Application",
                                $"[STARTUP] Background startup thread failed: {ex.Message}",
                                EventLogEntryType.Error, 1002);
                        }
                    });
                    startupThread.IsBackground = true;
                    startupThread.Name = "StartupReplay";
                    startupThread.Start();

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

        private void EnsurCheckpointBootstrap() => EnsureCheckpointBootstrap();

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

        private async Task ReplayMissedEventsFromCheckpoint()
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

                    // Opsi 3: Replay dari RawEventStore sebagai fallback tambahan.
                    // Ini menangkap 4624/4647 yang sudah hilang dari Security log tapi
                    // sempat disimpan ke rawevents\ saat terjadi.
                    await ReplayFromRawStore(replayFrom.Value, replayTo);

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
                // atau DataDirectory baru dibersihkan. Replay dari 00:00 hari ini (local time)
                // agar event login pagi (sebelum service pertama kali distart) ikut masuk.
                // Tidak replay lebih jauh agar tidak flood Security log historical.
                DateTime todayMidnightLocal = DateTime.Today.ToUniversalTime(); // local midnight → UTC
                SafeWriteEventLog("Application",
                    $"LoadStopCheckpoint: FRESH INSTALL — no checkpoint found anywhere. " +
                    $"Seeding replayFrom to today local midnight {todayMidnightLocal:O} " +
                    $"so events from 00:00 local today are captured.",
                    EventLogEntryType.Warning, 1023);
                return todayMidnightLocal;
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
            // Replay progress (termasuk 1029 "no checkpoint found" — kondisi normal fresh install)
            1029, 1030, 1031, 1032, 1033, 1034,
            // RawEventStore replay detail
            1036,
            // Live event skip & duplicate skip — normal behavior, bukan error
            1016, 1037, 1038,
            // Debug system event parsing — semua [DBG-*]
            2001, 2002, 2003, 2004, 2005, 2006, 2007, 2010, 2011, 2012, 2020, 2021,
            // Debug fallback resolution detail — [DBG-1074] resolved, [DBG-6005] ignored/skip/allow
            2013, 2014, 2024, 2025,
            // Debug RawEventStore fallback — [DBG-4624], [DBG-6005], [DBG-GetMRU], [DBG-42]
            2027, 2028, 2030, 2031, 2032,
            // SharePoint summary detail
            3001, 3002, 3003, 3004, 3005, 3007, 3008,
            3010, 3011, 3012, 3013, 3014, 3015, 3016, 3017, 3018, 3021, 3022,
            // Dispatch detail (per-event, terlalu sering di production)
            4002, 4003, 4004, 4005, 4006, 4007, 4008, 4009, 4010,
            // Event 42 last-resort promotion
            4011,
            // RAW insert success detail
            4020, 4021, 4022, 4025,
            // Cleanup progress detail
            5001, 5002, 5003, 5006,
            // Catatan: 0 (start), 1048 (ready), 1050 (OnStop), 1051 (OnShutdown)
            // sengaja TIDAK ada di sini — lifecycle events selalu tampil.
        };

        private void SaveReplayCheckpoint(DateTime checkpoint)
        {
            try
            {
                string? dir = Path.GetDirectoryName(replayCheckpointPath);
                if (!string.IsNullOrWhiteSpace(dir) && !Directory.Exists(dir))
                    Directory.CreateDirectory(dir);

                // Tulis atomik via temp+rename agar tidak corrupted kalau process mati di tengah write.
                string content = checkpoint.ToUniversalTime().ToString("O");
                string tempPath = replayCheckpointPath + ".tmp";
                File.WriteAllText(tempPath, content);
                File.Move(tempPath, replayCheckpointPath, overwrite: true);
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

                // Pre-filter 4624: skip irrelevant logon types dan admin split token early
                if (eventId == 4624 && entry.Message != null)
                {
                    int lt = ParseLogonType(entry.Message);
                    if (!IsRelevantLogonType(lt) || IsAdminSplitTokenLogin(entry.Message))
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

                // Opt 3: simpan raw event ke RawEventStore selama replay startup,
                // bukan hanya saat live (OnSecurityEventWritten).
                // Tanpa ini, kalau 4624 pagi ketahuan saat replay (bukan live) dan Security log
                // kemudian ter-rotate sebelum besok, data hilang lagi dari RawEventStore.
                _ = Task.Run(() => SaveRawSecurityEventAsync(entry));

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
                if (eventId != 1074 && eventId != 6006 && eventId != 6008 && eventId != 6005 && eventId != 41 && eventId != 42)
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

        /// <summary>
        /// Opsi 3: Replay 4624/4647 yang tersimpan di RawEventStore untuk window replayFrom–replayTo.
        /// Ini fallback kalau Security log sudah ter-rotate/clear sebelum ReplaySecurityEvents bisa baca.
        /// DedupWindow di EnqueueIfNotDuplicateAsync akan otomatis skip event yang sudah ada di queue.
        /// </summary>
        private async Task ReplayFromRawStore(DateTime replayFrom, DateTime replayTo)
        {
            try
            {
                DateTime localFrom = replayFrom.ToLocalTime().Date;
                DateTime localTo   = replayTo.ToLocalTime().Date;
                int totalProcessed = 0;

                for (DateTime date = localFrom; date <= localTo; date = date.AddDays(1))
                {
                    // Struktur flat: rawevents\{yyyyMMdd}\ — tidak ada subfolder per PC
                    var events4624 = rawEventStore.GetEventsForDate(date, 4624);
                    var events4647 = rawEventStore.GetEventsForDate(date, 4647);

                    var allEvents = events4624.Concat(events4647)
                        .Where(e => e.EventTimeUtc >= replayFrom && e.EventTimeUtc <= replayTo)
                        .OrderBy(e => e.EventTimeUtc)
                        .ToList();

                    foreach (var raw in allEvents)
                    {
                        // Skip kalau event ini sudah fully dispatched di queue
                        // (beyond DedupWindow 30 detik — tidak akan terdedup otomatis).
                        if (await IsAlreadyFullyDispatchedInQueueAsync(raw))
                            continue;

                        try
                        {
                            await ProcessRawSecurityEventAsync(raw, writeRawRecord: true);
                            totalProcessed++;
                        }
                        catch (Exception ex)
                        {
                            SafeWriteEventLog("Application",
                                $"[RAW-REPLAY] Error processing raw event id={raw.EventId} " +
                                $"computer={raw.ComputerName} time={raw.EventTimeUtc:O}: {ex.Message}",
                                EventLogEntryType.Warning, 1036);
                        }
                    }
                }

                if (totalProcessed > 0)
                {
                    SafeWriteEventLog("Application",
                        $"[RAW-REPLAY] Replayed {totalProcessed} raw security events from RawEventStore " +
                        $"({replayFrom:O} – {replayTo:O})",
                        EventLogEntryType.Information, 1036);
                }
            }
            catch (Exception ex)
            {
                SafeWriteEventLog("Application",
                    $"[RAW-REPLAY] Error in ReplayFromRawStore: {ex.Message}",
                    EventLogEntryType.Warning, 1036);
            }
        }

        /// <summary>
        /// Fix 6: Cek apakah raw event sudah ada di queue sebagai fully dispatched item.
        /// Dipakai di ReplayFromRawStore untuk skip event yang sudah diproses sebelumnya
        /// tapi di luar DedupWindow sehingga tidak akan terdedup otomatis oleh EnqueueIfNotDuplicateAsync.
        /// </summary>
        private async Task<bool> IsAlreadyFullyDispatchedInQueueAsync(RawSecurityEvent raw)
        {
            // #2: Pakai IsFullyDispatchedAsync di queue (cache-backed), tidak ada blocking call.
            try
            {
                return await eventQueue.IsFullyDispatchedAsync(
                    raw.EventId, raw.ComputerName, raw.EventTimeUtc);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Process sebuah RawSecurityEvent (dari RawEventStore) seperti halnya ProcessSecurityEntryAsync,
        /// tapi tanpa perlu EventLogEntry — pakai data yang sudah di-extract saat save.
        /// </summary>
        private async Task ProcessRawSecurityEventAsync(RawSecurityEvent raw, bool writeRawRecord)
        {
            try
            {
                int eventId      = raw.EventId;
                DateTime eventTime = raw.EventTimeUtc;
                string computerName = raw.ComputerName;
                int logonType    = raw.LogonType;

                if (eventId == 4624 && !IsRelevantLogonType(logonType))
                    return;

                // FIX (defense-in-depth): skip admin split token saat replay dari RawEventStore.
                // Normalnya SaveRawSecurityEventAsync sudah tidak menyimpan event admin ke disk,
                // tapi file lama (sebelum fix) mungkin masih ada di rawevents\ dan akan di-replay.
                // MessageExcerpt berisi section "New Logon:" yang include "Linked Logon ID:" dan
                // "Elevated Token:" — cukup untuk re-detect tanpa full message.
                if (eventId == 4624 && IsAdminSplitTokenLogin(raw.MessageExcerpt))
                    return;

                string? username = raw.Username;
                string? sid      = raw.Sid;

                if (!string.IsNullOrEmpty(username))
                    username = ResolveUsernameBySid(username, sid);

                if (string.IsNullOrEmpty(username) || !IsValidUsername(username))
                {
                    if (eventId == 4647)
                    {
                        await ProcessEvent(
                            4647, "__UNRESOLVED__", eventTime, computerName,
                            "Security", logonType, null, writeRawRecord,
                            usernameResolutionSource: "FallbackSecurity_Pending",
                            originalUsername: username,
                            fallbackSource: "Event4647_Pending",
                            isFallback: true, resolvedUsername: null,
                            status: "UNCONFIRMED", pendingUsernameResolution: true);
                    }
                    return;
                }

                if (eventId == 4624)
                {
                    lock (userLock)
                        lastActiveUser = username;
                    lock (knownLoginLock)
                        lastKnownLoginByComputer[computerName] = (username, eventTime);
                    RegisterFirst4624Logon(computerName, username, eventTime);
                }

                await ProcessEvent(eventId, username, eventTime, computerName,
                    "Security", logonType, null, writeRawRecord);
            }
            catch (Exception ex)
            {
                SafeWriteEventLog("Application",
                    $"Error in ProcessRawSecurityEventAsync: {ex.Message}",
                    EventLogEntryType.Warning, 1009);
            }
        }

        /// <summary>
        /// Hitung bucket device (0 sampai intervalDays-1) untuk menentukan hari cleanup SharePoint.
        /// Strategi: ekstrak angka di akhir nama komputer sebagai bucket utama.
        /// Format nama komputer: KODENAMECOMPANY-PC21, KODENAMECOMPANY-LAPTOP21, dst.
        /// Angka suffix (21, 5, dst) cenderung unik per device dan terdistribusi merata.
        /// Fallback ke stable hash (FNV-1a) kalau tidak ada angka di akhir nama.
        /// CATATAN: String.GetHashCode() tidak deterministik lintas restart di .NET Core 2.1+
        /// (randomized per-process). Pakai FNV-1a agar bucket sama setiap service restart.
        /// </summary>
        private static int GetDeviceCleanupBucket(string machineName, int intervalDays)
        {
            // Ekstrak angka di akhir nama komputer: "COMPANY-PC21" → 21
            var match = System.Text.RegularExpressions.Regex.Match(
                machineName, @"(\d+)\s*$", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (match.Success && int.TryParse(match.Groups[1].Value, out int suffix))
                return suffix % intervalDays;

            // Fallback: FNV-1a 32-bit — stable dan deterministik lintas restart
            return StableFnv1aHash(machineName) % intervalDays;
        }

        /// <summary>FNV-1a 32-bit hash — deterministic, tidak bergantung runtime seed.</summary>
        private static int StableFnv1aHash(string input)
        {
            unchecked
            {
                uint hash = 2166136261u;
                foreach (char c in input.ToUpperInvariant())
                {
                    hash ^= c;
                    hash *= 16777619u;
                }
                return (int)(hash & 0x7FFFFFFF); // always non-negative
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
            queueAlertThreshold = Math.Max(1, ReadIntFromEnvironment("QUEUE_ALERT_THRESHOLD", 500));
            int startupGapMinutes = ReadIntFromEnvironment("STARTUP_TO_FIRST_4624_MAX_GAP_MINUTES", 90);
            startupToFirst4624MaxGapForDirectUse = TimeSpan.FromMinutes(Math.Max(1, startupGapMinutes));
            dispatchBackoffSeconds = ReadIntListFromEnvironment(
                "DISPATCH_BACKOFF_SECONDS", new[] { 30, 60, 120, 300, 600 });

            return config;
        }

        private static int ReadIntFromEnvironment(string key, int fallback)
        {
            try
            {
                string? raw = Environment.GetEnvironmentVariable(key);
                if (int.TryParse(raw, out int parsed) && parsed > 0)
                    return parsed;
            }
            catch (Exception ex)
            {
                SafeWriteEventLog("Application",
                    $"[CONFIG] Failed to read env '{key}' as int. Using fallback={fallback}. Error={ex.Message}",
                    EventLogEntryType.Warning, 2030);
            }

            return fallback;
        }

        private static int[] ReadIntListFromEnvironment(string key, int[] fallback)
        {
            try
            {
                string? raw = Environment.GetEnvironmentVariable(key);
                if (string.IsNullOrWhiteSpace(raw))
                    return fallback;

                var values = new List<int>();
                string[] tokens = raw.Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (string token in tokens)
                {
                    if (int.TryParse(token, out int n) && n > 0)
                        values.Add(n);
                }

                return values.Count > 0 ? values.ToArray() : fallback;
            }
            catch (Exception ex)
            {
                SafeWriteEventLog("Application",
                    $"[CONFIG] Failed to read env '{key}' as int list. Using fallback. Error={ex.Message}",
                    EventLogEntryType.Warning, 2031);
                return fallback;
            }
        }

        // ─── Lifecycle ───────────────────────────────────────────────────────────

        protected override void OnStop() => HandleServiceStopping("OnStop", 1050);

        /// <summary>
        /// Called by SCM during Windows system shutdown/restart (requires CanShutdown = true).
        /// OnStop() is NOT guaranteed to be called in that scenario.
        /// </summary>
        protected override void OnShutdown() => HandleServiceStopping("OnShutdown", 1051);

        private void HandleServiceStopping(string caller, int stopEventId)
        {
            try
            {
                // Log segera saat stop dipanggil — sebelum checkpoint dan cleanup,
                // agar muncul di Event Viewer meski Windows kill process sebelum selesai.
                SafeWriteEventLog("Attendance-Service",
                    $"Service stopping ({caller}).",
                    EventLogEntryType.Information, stopEventId);

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
                    $"Service stopped ({caller}).",
                    EventLogEntryType.Information, stopEventId);
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
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    DateTime nowUtc = DateTime.UtcNow;
                    QueuedAttendanceEvent? next = await eventQueue.PeekNextReadyAsync(nowUtc, cancellationToken);
                    if (next == null)
                    {
                        DateTime? earliestRetryUtc = await eventQueue.GetEarliestNextRetryUtcAsync(cancellationToken);
                        TimeSpan wait = TimeSpan.FromSeconds(5);
                        if (earliestRetryUtc.HasValue && earliestRetryUtc.Value > nowUtc)
                        {
                            TimeSpan untilRetry = earliestRetryUtc.Value - nowUtc;
                            wait = untilRetry > TimeSpan.FromSeconds(30) ? TimeSpan.FromSeconds(30) : untilRetry;
                            if (wait < TimeSpan.FromSeconds(1))
                                wait = TimeSpan.FromSeconds(1);
                        }

                        await Task.Delay(wait, cancellationToken);
                        continue;
                    }

                    if (IsPendingQueueItemExpired(next, nowUtc))
                    {
                        await eventQueue.RemoveByIdAsync(next.QueueId, cancellationToken);
                        SafeWriteEventLog("Application",
                            $"[QUEUE] Expired pending item removed: queueId={next.QueueId} eventId={next.EventId} eventTime={next.EventTime:O}",
                            EventLogEntryType.Warning, 1047);
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

                    int retryCount = next.DispatchRetryCount + 1;
                    TimeSpan retryDelay = GetDispatchBackoffDelay(retryCount);
                    DateTime nextRetryAtUtc = DateTime.UtcNow.Add(retryDelay);
                    await eventQueue.UpdateRetryStateAsync(
                        next.QueueId,
                        retryCount,
                        nextRetryAtUtc,
                        next.LastDispatchError ?? "Dispatch failed",
                        cancellationToken);

                    SafeWriteEventLog("Application",
                        $"[DISPATCH] Retry scheduled queueId={next.QueueId} eventId={next.EventId} user={next.Username} " +
                        $"attempt={retryCount} nextRetryAt={nextRetryAtUtc:O} delay={retryDelay.TotalSeconds:F0}s",
                        EventLogEntryType.Warning, 1039);
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

        private TimeSpan GetDispatchBackoffDelay(int retryCount)
        {
            int index = Math.Clamp(retryCount - 1, 0, dispatchBackoffSeconds.Length - 1);
            return TimeSpan.FromSeconds(dispatchBackoffSeconds[index]);
        }

        private static bool IsPendingQueueItemExpired(QueuedAttendanceEvent item, DateTime nowUtc)
        {
            DateTime eventTimeUtc = item.EventTime.Kind == DateTimeKind.Unspecified
                ? DateTime.SpecifyKind(item.EventTime, DateTimeKind.Utc)
                : item.EventTime.ToUniversalTime();

            return nowUtc - eventTimeUtc > PendingQueueRetention;
        }

        private static bool ShouldProcessSummary(QueuedAttendanceEvent item)
        {
            // Login events (4624 normal, 6005 fallback): summary hanya first login of day.
            if (item.EventId == 4624 || item.EventId == 6005)
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

            if (item.EventId == 1074 || item.EventId == 6006 ||
                item.EventId == 4647 || item.EventId == 6008 || item.EventId == 41)
                return true;

            // FIX [BUG-2+3]: Event 42 (Sleep/Modern Standby) sebagai last-resort shutdown.
            // Hanya masuk summary kalau belum ada ShutdownTime sama sekali (IsLastResort42 flag).
            // Validasi wake (apakah 42 ini shutdown final) dilakukan di TryDispatchQueuedEventAsync.
            if (item.EventId == 42)
                return item.IsLastResort42;

            return false;
        }

        /// <summary>
        /// Priority untuk shutdown group — harus konsisten dengan SharePointIntegration.GetShutdownPriority.
        /// Dipakai untuk menentukan event mana di group yang boleh dispatch summary saat timer expired.
        ///   4647 = 6 (HIGHEST — explicit logoff, reliable di sleep/fast-startup/hibernate)
        ///   6006 confirmed = 5 | 1074 shutdown = 4 | 6008/41 = 1 | 42 = 0 (last resort)
        /// </summary>
        private static int GetShutdownEventPriority(int eventId, string eventType)
        {
            if (eventId == 4647) return 6; // Priority tertinggi — explicit user logoff dari Security log
            if (eventId == 6006)
                return eventType.Contains("unconfirmed", StringComparison.OrdinalIgnoreCase) ? 0 : 5;
            if (eventId == 1074 && !eventType.Contains("restart", StringComparison.OrdinalIgnoreCase)
                                && !eventType.Contains("reboot", StringComparison.OrdinalIgnoreCase)) return 4;
            if (eventId == 6008) return 1;
            if (eventId == 41)   return 1;
            if (eventId == 42)   return 0; // last resort — hanya kalau tidak ada event lain
            return 0;
        }

        private async Task<bool> TryDispatchQueuedEventAsync(QueuedAttendanceEvent item)
        {
            try
            {
                if (item.PendingUsernameResolution)
                {
                    bool resolved = item.EventId == 6005
                        ? await TryResolvePending6005UsernameAsync(item)
                        : await TryResolvePendingSystemUsernameAsync(item);
                    if (!resolved)
                    {
                        item.LastDispatchError ??= $"{item.EventId} username is still unresolved";
                        return false;
                    }
                }

                var sharePoint = sharePointIntegration.Value;
                string? accessToken = await sharePoint.GetAccessTokenAsync(item.EventTime, item.EventId);
                if (string.IsNullOrEmpty(accessToken))
                {
                    item.LastDispatchError = "Access token is null";
                    SafeWriteEventLog("Application",
                        $"[DISPATCH] Token null — skipping queueId={item.QueueId} eventId={item.EventId} user={item.Username}",
                        EventLogEntryType.Warning, 4001);
                    return false;
                }

                bool needsRaw     = item.WriteRawRecord && !item.RawRecordDispatched;
                bool needsSummary = ShouldProcessSummary(item) && !item.SummaryDispatched;

                // FIX [BUG-2+3]: Evaluasi apakah event 42 layak jadi last-resort ShutdownTime.
                // Dilakukan di sini (saat dispatch, bukan enqueue) karena kita perlu cek
                // apakah ada event shutdown "lebih baik" yang sudah masuk queue setelahnya.
                if (item.EventId == 42 && !item.IsLastResort42 && !item.SummaryDispatched)
                {
                    bool shouldUse42 = await ShouldUseEvent42AsLastResortAsync(item);
                    if (shouldUse42)
                    {
                        item.IsLastResort42 = true;
                        await eventQueue.ReplaceAsync(item);
                        // Re-evaluate needsSummary setelah flag di-set
                        needsSummary = ShouldProcessSummary(item) && !item.SummaryDispatched;
                        SafeWriteEventLog("Application",
                            $"[DISPATCH] Event 42 promoted to last-resort shutdown: " +
                            $"queueId={item.QueueId} user={item.Username} computer={item.ComputerName} " +
                            $"time={item.EventTime:O}",
                            EventLogEntryType.Information, 4011);
                    }
                }

                // Shutdown group hold: tahan summary dispatch untuk 4647/1074/6006 sampai
                // group lengkap atau timer 10 detik habis.
                // Priority: 4647 (6) > 6006 confirmed (5) > 1074 (4).
                // Kalau ada 4647 di group → 4647 yang dispatch, yang lain di-skip.
                // Kalau tidak ada 4647 → 6006 confirmed yang dispatch kalau ada, fallback 1074.
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
                        // FIX [BUG-1]: Cek apakah 6006 di group adalah confirmed (paired 1074 shutdown).
                        // Kalau 6006 hanya unconfirmed (Fast Startup/restart), 4647 tetap boleh
                        // dispatch summary — jangan skip, karena unconfirmed 6006 tidak update summary.
                        bool confirmedExists = await eventQueue.GroupHasConfirmed6006Async(item.ShutdownGroupId);
                        if (confirmedExists)
                        {
                            // 4647 priority lebih tinggi dari confirmed 6006 (6 vs 5) —
                            // kalau item ini 4647, biarkan dia dispatch, bukan 6006.
                            if (item.EventId == 4647)
                            {
                                // 4647 menang — mark 6006 di group sebagai summaryDispatched
                                // agar 6006 tidak kirim summary lagi setelahnya.
                                await eventQueue.MarkGroupSummaryDispatchedAsync(item.ShutdownGroupId, exceptQueueId: item.QueueId);
                                SafeWriteEventLog("Application",
                                    $"[DISPATCH] Shutdown group: 4647 takes priority over confirmed 6006. " +
                                    $"queueId={item.QueueId} groupId={item.ShutdownGroupId}",
                                    EventLogEntryType.Information, 4009);
                                // needsSummary tetap true — 4647 yang dispatch
                            }
                            else
                            {
                                // Bukan 4647 — confirmed 6006 yang dispatch summary (priority lebih tinggi).
                                needsSummary = false;
                                SafeWriteEventLog("Application",
                                    $"[DISPATCH] Shutdown group: confirmed 6006 in group, skipping summary for " +
                                    $"queueId={item.QueueId} eventId={item.EventId}",
                                    EventLogEntryType.Information, 4009);
                                await eventQueue.UpdateDispatchStateAsync(item.QueueId, summaryDispatched: true);
                                item.SummaryDispatched = true;
                            }
                        }
                        else
                        {
                            // 6006 di group hanya unconfirmed → tidak update summary.
                            // Biarkan 4647 (atau event prioritas tertinggi lain) yang dispatch.
                            SafeWriteEventLog("Application",
                                $"[DISPATCH] Shutdown group: only unconfirmed 6006 in group, " +
                                $"allowing {item.EventId} to dispatch summary. " +
                                $"queueId={item.QueueId} groupId={item.ShutdownGroupId}",
                                EventLogEntryType.Information, 4009);
                        }
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
                    if (item.EventId == 4624 || item.EventId == 6005)
                    {
                        SafeWriteEventLog("Application",
                            $"[DISPATCH] Sending summary login: user={item.Username} computer={item.ComputerName} " +
                            $"loginTime={item.LoginTime?.ToString("O") ?? item.EventTime.ToString("O")}",
                            EventLogEntryType.Information, 4004);

                        await sharePoint.UpsertDailySummaryLoginAsync(
                            accessToken, item.Username, item.ComputerName,
                            item.LoginTime ?? item.EventTime, summaryCache, item.Status);
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
                            item.EventId, item.EventType,
                            allLogon4624ByDeviceWorkDate,
                            summaryCache);
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

                item.LastDispatchError = null;
                return doneRaw && doneSummary;
            }
            catch (Exception ex)
            {
                item.LastDispatchError = $"{ex.GetType().Name}: {ex.Message}";
                SafeWriteEventLog("Application",
                    $"Dispatch failed: queueId={item.QueueId} eventId={item.EventId} user={item.Username} " +
                    $"time={item.EventTime:O} error={ex.GetType().Name}: {ex.Message}",
                    EventLogEntryType.Warning, 1028);
                return false;
            }
        }

        // ─── Cleanup ─────────────────────────────────────────────────────────────

        /// <summary>
        /// Cleanup task dengan strategi:
        ///
        /// LOCAL (RawEventStore + SummaryCache):
        ///   Jalan setiap hari saat service startup (missedCleanup), tidak perlu koordinasi.
        ///   Tidak ada contention — masing-masing device manage file lokalnya sendiri.
        ///
        /// SHAREPOINT (raw list + summary list):
        ///   Shared resource — perlu spread agar tidak semua device query Graph API bersamaan.
        ///   Strategi:
        ///   1. Window cleanup: 07:00–09:00 (saat device baru nyala, bukan jam 03:00 saat mati).
        ///   2. Slot deterministik per device: StableFnv1aHash(MachineName) % 120 menit.
        ///      → 100 device tersebar merata dalam 120 menit = rata-rata 1 device / 1.2 menit.
        ///   3. Jitter hari: SharePoint cleanup hanya jalan setiap 3 hari per device.
        ///      → Further reduce load, data lama tidak urgent dihapus hari itu juga.
        ///   4. Guard lastSharePointCleanupDate: tidak dobel meski service restart beberapa kali.
        /// </summary>
        private async Task CleanupOldRecordsTask(CancellationToken cancellationToken)
        {
            const int retentionMonths     = 6;
            const int sharePointCleanupWindowStartHour = 7;   // mulai jam 07:00
            const int sharePointCleanupWindowMinutes   = 120; // window 2 jam (07:00–09:00)
            const int sharePointCleanupIntervalDays    = 3;   // SharePoint cleanup setiap 3 hari

            // Slot deterministik per device dalam window cleanup (0–119 menit dari jam 07:00).
            // Pakai deviceSlotMinutes untuk spread dalam window, GetDeviceCleanupBucket untuk
            // menentukan hari mana device ini cleanup SharePoint.
            // Slot deterministik per device dalam window cleanup (0–119 menit dari jam 07:00).
            // Pakai StableFnv1aHash agar slot sama setiap service restart — GetHashCode() di .NET Core
            // adalah randomized per-process sehingga tidak deterministik lintas restart.
            int deviceSlotMinutes = StableFnv1aHash(Environment.MachineName) % sharePointCleanupWindowMinutes;
            int deviceBucket      = GetDeviceCleanupBucket(Environment.MachineName, sharePointCleanupIntervalDays);

            DateTime lastLocalCleanupDate      = DateTime.MinValue.Date;
            DateTime lastSharePointCleanupDate = DateTime.MinValue.Date;

            SafeWriteEventLog("Application",
                $"[CLEANUP] Device slot: {sharePointCleanupWindowStartHour:D2}:{deviceSlotMinutes:D2} " +
                $"bucket={deviceBucket}/{sharePointCleanupIntervalDays} " +
                $"(suffix dari '{Environment.MachineName}' → cleanup tiap hari ke-{deviceBucket},{deviceBucket + sharePointCleanupIntervalDays},...). " +
                $"SharePoint cleanup every {sharePointCleanupIntervalDays} days.",
                EventLogEntryType.Information, 5001);

            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    DateTime now = DateTime.Now;

                    // ── LOCAL CLEANUP (setiap hari, saat startup) ─────────────────
                    // Tidak perlu koordinasi — jalan segera kalau belum cleanup hari ini.
                    if (lastLocalCleanupDate.Date < now.Date)
                    {
                        await summaryCache.CleanupOldEntriesAsync(cancellationToken);
                        await rawEventStore.CleanupOldDatesAsync(eventQueue, cancellationToken);
                        lastLocalCleanupDate = now.Date;
                        SafeWriteEventLog("Application",
                            $"[CLEANUP] Local cleanup done (summaryCache + rawEvents) for {now.Date:yyyy-MM-dd}.",
                            EventLogEntryType.Information, 5006);
                    }

                    // ── SHAREPOINT CLEANUP (setiap 3 hari, slot deterministik) ────
                    // Hari cleanup SharePoint untuk device ini:
                    // now.Day % intervalDays == deviceBucket
                    // Contoh intervalDays=3: PC21 (suffix 21, bucket=0) cleanup di hari 3,6,9,...
                    //                        PC22 (suffix 22, bucket=1) cleanup di hari 1,4,7,...
                    //                        PC23 (suffix 23, bucket=2) cleanup di hari 2,5,8,...
                    bool isSharePointCleanupDay = (now.Day % sharePointCleanupIntervalDays) == deviceBucket;

                    // Waktu slot device: jam 07:00 + deviceSlotMinutes
                    DateTime deviceCleanupTime = now.Date
                        .AddHours(sharePointCleanupWindowStartHour)
                        .AddMinutes(deviceSlotMinutes);

                    bool slotReached        = now >= deviceCleanupTime;
                    bool notYetCleanedToday = lastSharePointCleanupDate.Date < now.Date;

                    if (isSharePointCleanupDay && slotReached && notYetCleanedToday)
                    {
                        SafeWriteEventLog("Application",
                            $"[CLEANUP] SharePoint cleanup starting — slot={deviceCleanupTime:HH:mm} " +
                            $"device={Environment.MachineName}",
                            EventLogEntryType.Information, 5001);

                        await sharePointIntegration.Value.CleanupOldRecordsAsync(retentionMonths);
                        lastSharePointCleanupDate = now.Date;

                        SafeWriteEventLog("Application",
                            $"[CLEANUP] SharePoint cleanup done for {now.Date:yyyy-MM-dd}.",
                            EventLogEntryType.Information, 5001);
                    }

                    // ── Hitung waktu tunggu ke event berikutnya ───────────────────
                    // Kandidat: (1) slot SharePoint hari ini, (2) slot SharePoint hari cleanup berikutnya,
                    // (3) local cleanup besok jam 00:01.
                    DateTime nextLocalCleanup = now.Date.AddDays(1).AddMinutes(1);

                    // Cari hari cleanup SharePoint berikutnya
                    DateTime nextSharePointCleanup = deviceCleanupTime.AddDays(1); // default besok
                    for (int d = 0; d <= sharePointCleanupIntervalDays + 1; d++)
                    {
                        DateTime candidate = now.Date.AddDays(d)
                            .AddHours(sharePointCleanupWindowStartHour)
                            .AddMinutes(deviceSlotMinutes);
                        if (candidate > now && (candidate.Day % sharePointCleanupIntervalDays) == deviceBucket)
                        {
                            nextSharePointCleanup = candidate;
                            break;
                        }
                    }

                    DateTime nextWakeUp = new[] { nextLocalCleanup, nextSharePointCleanup }
                        .Where(t => t > now)
                        .DefaultIfEmpty(now.AddHours(1))
                        .Min();

                    // Maksimum tidur 1 jam agar tidak terlalu lama kalau ada drift
                    TimeSpan sleepDuration = nextWakeUp - now;
                    if (sleepDuration > TimeSpan.FromHours(1))
                        sleepDuration = TimeSpan.FromHours(1);
                    if (sleepDuration < TimeSpan.FromSeconds(30))
                        sleepDuration = TimeSpan.FromSeconds(30);

                    await Task.Delay(sleepDuration, cancellationToken);
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

            // Opsi 3: simpan raw event ke disk SEBELUM diproses, agar tidak hilang
            // kalau Security log ter-rotate/clear sebelum service sempat replay.
            _ = Task.Run(() => SaveRawSecurityEventAsync(entry));

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

        private volatile int _skipLogSuppressedCount = 0;
        // Ticks-based agar bisa diakses dengan Interlocked.Read (DateTime tidak thread-safe secara native)
        private long _lastSkipLogTimeTicks = DateTime.MinValue.Ticks;

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
                    // Rate-limit log 1038 — maksimal 1x per 30 detik, sisanya di-suppress.
                    // Pakai Interlocked agar aman dari concurrent OnSecurityEventWritten calls.
                    long lastTicks = Interlocked.Read(ref _lastSkipLogTimeTicks);
                    bool shouldLog = (DateTime.Now.Ticks - lastTicks) >= TimeSpan.FromSeconds(30).Ticks;
                    if (shouldLog)
                    {
                        int suppressed = Interlocked.Exchange(ref _skipLogSuppressedCount, 0);
                        Interlocked.Exchange(ref _lastSkipLogTimeTicks, DateTime.Now.Ticks);
                        string suffix = suppressed > 0
                            ? $" (+ {suppressed} suppressed)"
                            : string.Empty;
                        SafeWriteEventLog("Application",
                            $"Live event skipped — older than replayUpperBound: eventTime={eventTime:O} replayUpperBound={replayUpperBound:O}{suffix}",
                            EventLogEntryType.Information, 1038);
                    }
                    else
                    {
                        Interlocked.Increment(ref _skipLogSuppressedCount);
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
                {
                    if (eventId == 4647)
                    {
                        await ProcessEvent(
                            4647,
                            "__UNRESOLVED__",
                            eventTime,
                            computerName,
                            "Security",
                            logonType,
                            null,
                            writeRawRecord,
                            usernameResolutionSource: "FallbackSecurity_Pending",
                            originalUsername: username,
                            fallbackSource: "Event4647_Pending",
                            isFallback: true,
                            resolvedUsername: null,
                            status: "UNCONFIRMED",
                            pendingUsernameResolution: true);

                        SafeWriteEventLog("Application",
                            $"[DBG-4647] Username unresolved at {eventTime:O} on {computerName} — queued as pending.",
                            EventLogEntryType.Information, 2026);
                    }
                    return;
                }

                string? sid = GetUserSidFromSecurityEvent(eventMessage, eventId);
                username = ResolveUsernameBySid(username, sid);
                if (string.IsNullOrEmpty(username) || !IsValidUsername(username))
                {
                    if (eventId == 4647)
                    {
                        await ProcessEvent(
                            4647,
                            "__UNRESOLVED__",
                            eventTime,
                            computerName,
                            "Security",
                            logonType,
                            null,
                            writeRawRecord,
                            usernameResolutionSource: "FallbackSecurity_Pending",
                            originalUsername: null,
                            fallbackSource: "Event4647_Pending",
                            isFallback: true,
                            resolvedUsername: null,
                            status: "UNCONFIRMED",
                            pendingUsernameResolution: true);

                        SafeWriteEventLog("Application",
                            $"[DBG-4647] SID resolution failed at {eventTime:O} on {computerName} — queued as pending.",
                            EventLogEntryType.Information, 2026);
                    }
                    return;
                }

                if (eventId == 4624)
                {
                    lock (userLock)
                        lastActiveUser = username;
                    lock (knownLoginLock)
                        lastKnownLoginByComputer[computerName] = (username, eventTime);
                    RegisterFirst4624Logon(computerName, username, eventTime);
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
                if (eventId != 1074 && eventId != 6006 && eventId != 6008 && eventId != 6005 && eventId != 41 && eventId != 42)
                    return;

                DateTime eventTime = log.TimeGenerated.ToUniversalTime();
                string computerName = log.MachineName;
                string usernameResolutionSource = "Direct";
                string? originalUsername = null;
                string? fallbackSource = null;
                bool isFallback = false;
                string? resolvedUsername = null;
                string? status = null;
                bool pendingUsernameResolution = false;

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

                if (eventId == 6005)
                {
                    bool handled = await TryProcessFallbackLoginFrom6005Async(eventTime, computerName, writeRawRecord);
                    if (!handled)
                    {
                        SafeWriteEventLog("Application",
                            $"[DBG-6005] Event ignored at {eventTime:O} on {computerName} — no fallback login needed/resolved.",
                            EventLogEntryType.Information, 2014);
                    }
                    return;
                }

                string? eventMessage = (eventId == 1074) ? log.Message : null;
                string? username = (eventId == 1074) ? GetUserFromSystem1074Message(eventMessage) : null;

                if (eventId == 1074)
                {
                    SafeWriteEventLog("Application",
                        $"[DBG-1074] GetUserFromSystem1074Message returned: '{username ?? "(null)"}'",
                        EventLogEntryType.Information, 2003);
                }

                if (eventId == 1074)
                {
                    originalUsername = username;

                    bool fallbackRequired = string.IsNullOrWhiteSpace(username) ||
                                            IsSystemFallbackTriggerAccount(username) ||
                                            !IsValidUsername(username);

                    if (fallbackRequired)
                    {
                        string? resolvedFrom4624 = await ResolveFirst4624UsernameForWorkDateAsync(computerName, eventTime);
                        if (!string.IsNullOrWhiteSpace(resolvedFrom4624))
                        {
                            username = resolvedFrom4624;
                            usernameResolutionSource = "Fallback4624";
                            resolvedUsername = resolvedFrom4624;
                            isFallback = true;
                            fallbackSource = "FirstLogon4624";
                            SafeWriteEventLog("Application",
                                $"[DBG-1074] Fallback resolved username='{username}' from 4624 " +
                                $"(original='{originalUsername ?? "(null)"}', computer='{computerName}')",
                                EventLogEntryType.Information, 2013);
                        }
                        else
                        {
                            string? queueRecent4624 = await eventQueue.FindMostRecent4624UsernameForComputerAsync(computerName, eventTime);
                            if (!string.IsNullOrWhiteSpace(queueRecent4624) && IsValidUsername(queueRecent4624))
                            {
                                username = queueRecent4624;
                                usernameResolutionSource = "Fallback4624Queue";
                                resolvedUsername = queueRecent4624;
                                isFallback = true;
                                fallbackSource = "Event1074_Queue4624";
                                SafeWriteEventLog("Application",
                                    $"[DBG-1074] Fallback resolved username='{username}' from nearest queue 4624 " +
                                    $"(original='{originalUsername ?? "(null)"}', computer='{computerName}')",
                                    EventLogEntryType.Information, 2013);
                            }
                        }

                        if (string.IsNullOrWhiteSpace(username) || !IsValidUsername(username))
                        {
                            var sharePointLookup = await sharePointIntegration.Value.GetLatestUsernameByComputerWithStatusAsync(computerName, eventTime);
                            string? fromSharePoint = sharePointLookup.Username;
                            if (!string.IsNullOrWhiteSpace(fromSharePoint) && IsValidUsername(fromSharePoint))
                            {
                                username = fromSharePoint;
                                usernameResolutionSource = "FallbackSharePoint";
                                resolvedUsername = fromSharePoint;
                                isFallback = true;
                                fallbackSource = "Event1074_SharePoint";
                                SafeWriteEventLog("Application",
                                    $"[DBG-1074] Fallback resolved username='{username}' from SharePoint latest by computer " +
                                    $"(original='{originalUsername ?? "(null)"}', computer='{computerName}')",
                                    EventLogEntryType.Information, 2013);
                            }
                        }

                        if (string.IsNullOrWhiteSpace(username) || !IsValidUsername(username))
                        {
                            username = "__UNRESOLVED__";
                            usernameResolutionSource = "FallbackSystem_Pending";
                            resolvedUsername = null;
                            isFallback = true;
                            fallbackSource = "Event1074_Pending";
                            status = "UNCONFIRMED";
                            pendingUsernameResolution = true;
                            SafeWriteEventLog("Application",
                                $"[DBG-1074] Username unresolved at {eventTime:O} on {computerName} — queued as pending.",
                                EventLogEntryType.Warning, 2008);
                        }
                    }
                }

                if (eventId == 1074 && !pendingUsernameResolution &&
                    !string.IsNullOrWhiteSpace(username) && IsValidUsername(username))
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
                }

                if (string.IsNullOrEmpty(username) || !IsValidUsername(username))
                {
                    username = "__UNRESOLVED__";
                    pendingUsernameResolution = true;
                    status ??= "UNCONFIRMED";
                    isFallback = true;
                    resolvedUsername = null;
                    usernameResolutionSource = "FallbackSystem_Pending";
                    fallbackSource ??= BuildPendingFallbackSource(eventId);
                    SafeWriteEventLog("Application",
                        $"[DBG-{eventId}] Username unresolved at {eventTime:O} — queued as pending ({fallbackSource}).",
                        EventLogEntryType.Warning, 2008);
                }

                if (eventId == 42)
                    SharePointIntegration.MarkSleepEvent(eventTime);

                await ProcessEvent(eventId, username, eventTime, computerName,
                    "System", 0, eventMessage, writeRawRecord,
                    usernameResolutionSource, originalUsername, fallbackSource,
                    isFallback, resolvedUsername, status, pendingUsernameResolution);
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
            bool writeRawRecord,
            string usernameResolutionSource = "Direct",
            string? originalUsername = null,
            string? fallbackSource = null,
            bool isFallback = false,
            string? resolvedUsername = null,
            string? status = null,
            bool pendingUsernameResolution = false)
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
                        6005 => "UNCONFIRMED - Fallback from Event 6005, Security Log unavailable",
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

                if (eventId == 4624 || eventId == 6005)
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
                // Fix 7: event 42 (Sleep) juga set shutdownTime secara eksplisit.
                // Sebelumnya null dan fallback ke EventTime saat dispatch — ini tetap benar
                // tapi tidak konsisten. Set eksplisit di sini agar ShutdownTime tersimpan
                // di queue file dan tidak bergantung pada fallback ?? EventTime saat dispatch.
                else if (eventId == 42)
                {
                    shutdownTime = eventTime;
                    shutdownType = $"42 - {eventType}";
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
                    WriteRawRecord  = writeRawRecord,
                    UsernameResolutionSource = usernameResolutionSource,
                    ResolvedUsername = resolvedUsername,
                    OriginalUsername = originalUsername,
                    IsFallback = isFallback,
                    FallbackSource = fallbackSource,
                    Status = status,
                    PendingUsernameResolution = pendingUsernameResolution
                };

                // Shutdown group: 1074 dan 6006 yang terjadi berbarengan dikelompokkan
                // agar 6006 bisa ambil username dari 1074 yang berdekatan dan summary hanya
                // di-dispatch satu kali per rangkaian shutdown.
                // 4647 TIDAK di-group: dia punya username sendiri dari Security log, tidak butuh
                // pairing, dan ikut group justru menyebabkan bug — kalau 4647 muncul di rangkaian
                // shutdown berbeda (sesi baru) tapi epoch90s-nya collision dengan group lama,
                // MarkGroupSummaryDispatchedAsync akan mark 4647 baru sebagai sudah dispatch
                // padahal belum, sehingga logout time tidak terupdate ke waktu yang lebih baru.
                // 4647 langsung dispatch ke TryUpdateDailySummaryShutdownAsync; priority system
                // di sana sudah cukup sebagai arbiter (4647=6, highest priority).
                // 6008 dan 41 tidak di-group karena mereka standalone (tidak ada paired event).
                if (eventId == 1074 || eventId == 6006)
                {
                    string workDate = eventTime.ToLocalTime().ToString("yyyy-MM-dd");
                    // #7: Pakai window 90 detik (epoch / 90) bukan 1 menit penuh (epoch / 60).
                    // epochMinute menyebabkan collision: 1074 jam 17:00:01 dan 1074 jam 17:01:30
                    // dari sesi berbeda masuk group yang sama karena epochMinute = (total detik / 60)
                    // bisa sama untuk dua menit berbeda kalau ada event di detik-detik akhir menit.
                    // 90 detik lebih dari cukup untuk menampung seluruh rangkaian 4647+1074+6006
                    // yang biasanya fire dalam < 5 detik, tapi cukup sempit untuk hindari collision
                    // antara dua sesi berbeda yang terjadi dalam 1 jam yang sama.
                    long epoch90s = (long)(eventTime - DateTime.UnixEpoch).TotalSeconds / 90;
                    queuedEvent.ShutdownGroupId = $"shutdown_{computerName}_{username}_{workDate}_{epoch90s}";
                    // Fix 5: naikkan hold window dari 3 → 12 detik.
                    // 3 detik terlalu pendek kalau dispatch sedang backoff (network lambat)
                    // dan event group berikutnya (1074/6006) masuk setelah backoff delay.
                    // 12 detik masih aman saat shutdown — network biasanya bertahan 15-30 detik.
                    queuedEvent.ShutdownGroupHoldUntil = eventTime.AddSeconds(12);

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
                    await CheckQueueSizeThresholdAsync(cancellationToken: default);

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

        // ─── Opsi 3: Raw Event Store helpers ────────────────────────────────────────

        /// <summary>
        /// Simpan raw security event ke RawEventStore sebelum diproses.
        /// Hanya simpan event ID yang relevan (4624, 4647).
        /// Message excerpt dibatasi ke section yang diperlukan saja untuk hemat disk.
        /// </summary>
        private async Task SaveRawSecurityEventAsync(EventLogEntry entry)
        {
            try
            {
                int eventId = GetNormalizedEventId(entry);
                if (eventId != 4624 && eventId != 4647)
                    return;

                // Untuk 4624: ambil section "New Logon:" saja
                // Untuk 4647: ambil section "Subject:" saja
                string? excerpt = null;
                string? message = entry.Message;
                if (message != null)
                {
                    string anchor = eventId == 4624 ? "New Logon:" : "Subject:";
                    int idx = message.IndexOf(anchor, StringComparison.OrdinalIgnoreCase);
                    if (idx >= 0)
                    {
                        // Ambil max 600 char dari anchor untuk dapat Account Name + Security ID
                        int len = Math.Min(600, message.Length - idx);
                        excerpt = message.Substring(idx, len);
                    }
                }

                // FIX: jangan simpan event admin/privileged ke RawEventStore sama sekali.
                // Tanpa ini, event 4624 admin tersimpan ke disk dengan Username sudah ter-extract,
                // lalu saat ProcessRawSecurityEventAsync replay — yang tidak punya akses ke
                // full message — tidak bisa re-check split token dan akun admin lolos masuk queue.
                // IsAdminSplitTokenLogin cek Linked Logon ID non-0x0 DAN Elevated Token: Yes.
                if (eventId == 4624 && IsAdminSplitTokenLogin(message ?? excerpt))
                    return;

                string? username = message != null ? GetUsernameFromEvent(message, eventId) : null;
                string? sid      = message != null ? GetUserSidFromSecurityEvent(message, eventId) : null;
                int logonType    = (eventId == 4624 && message != null) ? ParseLogonType(message) : 0;

                var raw = new RawSecurityEvent
                {
                    EventId        = eventId,
                    ComputerName   = entry.MachineName,
                    EventTimeUtc   = entry.TimeGenerated.ToUniversalTime(),
                    LogonType      = logonType,
                    Username       = username,
                    Sid            = sid,
                    MessageExcerpt = excerpt,
                    Source         = "Security"
                };

                await rawEventStore.SaveAsync(raw);
            }
            catch { /* jangan crash service */ }
        }

        /// <summary>
        /// Replay raw security events dari RawEventStore untuk workDate tertentu.
        /// Dipanggil sebagai fallback di ResolveFirst4624ForWorkDateAsync dan
        /// IsSecurityLogUnavailableOrLikelyCleared kalau Security log lokal kosong.
        /// </summary>
        private List<RawSecurityEvent> GetRawEventsFromStore(string computerName, DateTime localDate, int eventId)
        {
            return rawEventStore.GetEventsForDate(computerName, localDate, eventId);
        }

        // ─── Helpers ─────────────────────────────────────────────────────────────

        private async Task RetryPendingQueueOnStartupAsync(CancellationToken cancellationToken)
        {
            try
            {
                int initialPending = await eventQueue.GetCountAsync(cancellationToken);
                if (initialPending == 0)
                    return;

                SafeWriteEventLog("Application",
                    $"[STARTUP] Pending queue detected: {initialPending} item(s). Retrying before new ingestion.",
                    EventLogEntryType.Warning, 1044);

                while (!cancellationToken.IsCancellationRequested)
                {
                    var next = await eventQueue.PeekNextReadyAsync(DateTime.UtcNow, cancellationToken);
                    if (next == null)
                        break;

                    if (IsPendingQueueItemExpired(next, DateTime.UtcNow))
                    {
                        await eventQueue.RemoveByIdAsync(next.QueueId, cancellationToken);
                        SafeWriteEventLog("Application",
                            $"[QUEUE] Expired pending item removed on startup: queueId={next.QueueId} eventId={next.EventId} eventTime={next.EventTime:O}",
                            EventLogEntryType.Warning, 1047);
                        continue;
                    }

                    bool sent = await TryDispatchQueuedEventAsync(next);
                    if (sent)
                    {
                        await eventQueue.RemoveByIdAsync(next.QueueId, cancellationToken);
                        continue;
                    }

                    int retryCount = next.DispatchRetryCount + 1;
                    TimeSpan retryDelay = GetDispatchBackoffDelay(retryCount);
                    DateTime nextRetryAt = DateTime.UtcNow.Add(retryDelay);
                    await eventQueue.UpdateRetryStateAsync(
                        next.QueueId,
                        retryCount,
                        nextRetryAt,
                        next.LastDispatchError ?? "Dispatch failed on startup retry",
                        cancellationToken);
                }
            }
            catch (Exception ex)
            {
                SafeWriteEventLog("Application",
                    $"[STARTUP] Pending queue retry pass failed: {ex.Message}",
                    EventLogEntryType.Warning, 1045);
            }
        }

        private async Task CheckQueueSizeThresholdAsync(CancellationToken cancellationToken)
        {
            int pending = await eventQueue.GetCountAsync(cancellationToken);

            if (pending > queueAlertThreshold && !queueThresholdAlerted)
            {
                queueThresholdAlerted = true;
                SafeWriteEventLog("Application",
                    $"[QUEUE] Pending queue high-water alert: {pending} item(s), threshold={queueAlertThreshold}.",
                    EventLogEntryType.Warning, 1046);
            }
            else if (pending <= Math.Max(1, (int)Math.Floor(queueAlertThreshold * 0.8)))
            {
                queueThresholdAlerted = false;
            }
        }

        private string? GetMostRecentUser(DateTime beforeTime)
        {
            try
            {
                DateTime lookbackTime = beforeTime.AddHours(-12);
                using EventLog secLog = new EventLog("Security");
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
        /// Dua kondisi ANY-of yang menyebabkan event di-skip:
        ///   1. Linked Logon ID (TargetLinkedLogonId) != 0x0  → bagian dari UAC split token pair.
        ///      Berlaku untuk KEDUA event (Elevated Token Yes maupun No) karena keduanya
        ///      punya linked logon ID yang saling pointing.
        ///   2. Elevated Token = Yes (%%1842 di XML / "Elevated Token: Yes" di plain-text)
        ///      → token high-integrity milik akun admin/privileged; tidak relevan untuk absensi.
        ///
        /// Catatan: %%1843 = No (non-elevated, user biasa) → LOLOS; %%1842 = Yes → SKIP.
        /// </summary>
        private static bool IsAdminSplitTokenLogin(string? message)
        {
            if (string.IsNullOrEmpty(message)) return false;
            try
            {
                // ── Cek 1: Linked Logon ID non-zero ─────────────────────────────────
                // "Linked Logon ID:\t\t0x42e9e44"  (plain-text EventLog format)
                // "TargetLinkedLogonId: 0x42e9e44"  (kadang muncul di excerpt berbeda)
                var linkedMatch = Regex.Match(message,
                    @"(?:Linked Logon ID|TargetLinkedLogonId):\s*(0x[0-9A-Fa-f]+)",
                    RegexOptions.IgnoreCase);
                if (linkedMatch.Success)
                {
                    string linkedId = linkedMatch.Groups[1].Value.Trim();
                    // 0x0 atau 0x0000000000000000 = tidak ada linked logon = bukan split token
                    if (Convert.ToInt64(linkedId, 16) != 0)
                        return true;
                }

                // ── Cek 2: Elevated Token = Yes ──────────────────────────────────────
                // Plain-text format: "Elevated Token:\t\tYes"
                // XML raw format:    "%%1842"  (Yes) vs "%%1843" (No)
                // Cukup satu dari dua format ini untuk mendeteksi elevated token.
                var elevatedMatch = Regex.Match(message,
                    @"Elevated Token:\s*(?:Yes|%%1842)",
                    RegexOptions.IgnoreCase);
                if (elevatedMatch.Success)
                    return true;

                return false;
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

                    string normalized = NormalizeDisplayUsername(accountName);
                    return IsValidUsername(normalized) ? normalized : null;
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

                    string normalized = NormalizeDisplayUsername(accountName);
                    return IsValidUsername(normalized) ? normalized : null;
                }
            }
            catch { /* silent fail */ }

            return null;
        }

        private string? GetMostRecentUserForComputer(
            DateTime beforeTime,
            string computerName,
            TimeSpan lookbackWindow,
            bool requireRelevant4624)
        {
            try
            {
                DateTime lookbackTime = beforeTime - lookbackWindow;
                using EventLog secLog = new EventLog("Security");
                int checkCount = 0;

                for (int i = secLog.Entries.Count - 1; i >= 0 && checkCount < 1000; i--)
                {
                    checkCount++;
                    EventLogEntry entry = secLog.Entries[i];
                    if (!entry.MachineName.Equals(computerName, StringComparison.OrdinalIgnoreCase))
                        continue;

                    int secEventId = GetNormalizedEventId(entry);
                    if (secEventId != 4624)
                        continue;

                    DateTime entryTime = entry.TimeGenerated.ToUniversalTime();
                    if (entryTime < lookbackTime || entryTime > beforeTime || entry.Message == null)
                        continue;

                    int lt = ParseLogonType(entry.Message);
                    if (requireRelevant4624 && !IsRelevantLogonType(lt))
                        continue;

                    string? u = GetUsernameFromEvent(entry.Message, secEventId);
                    if (!string.IsNullOrEmpty(u) && IsValidUsername(u))
                        return u;
                }
            }
            catch (Exception ex)
            {
                SafeWriteEventLog("Application",
                    $"GetMostRecentUserForComputer failed for computer='{computerName}': {ex.Message}",
                    EventLogEntryType.Warning, 2015);
            }

            // Opt 5: fallback ke RawEventStore kalau Security log miss (rotated/cleared).
            // Cari 4624 terbaru dalam lookback window yang sama.
            try
            {
                DateTime lookbackTime = beforeTime - lookbackWindow;
                DateTime localDate    = beforeTime.ToLocalTime().Date;

                // Scan tanggal hari ini dan kemarin (kalau lookback melewati midnight)
                var candidates = new List<RawSecurityEvent>();
                for (DateTime d = localDate.AddDays(-1); d <= localDate; d = d.AddDays(1))
                {
                    var raw = rawEventStore.GetEventsForDate(computerName, d, 4624);
                    candidates.AddRange(raw);
                }

                var best = candidates
                    .Where(r =>
                        r.EventTimeUtc >= lookbackTime &&
                        r.EventTimeUtc <= beforeTime &&
                        (!requireRelevant4624 || IsRelevantLogonType(r.LogonType)))
                    .OrderByDescending(r => r.EventTimeUtc)
                    .FirstOrDefault();

                if (best != null)
                {
                    string? rawUser = best.Username;
                    if (!string.IsNullOrWhiteSpace(rawUser))
                        rawUser = ResolveUsernameBySid(rawUser, best.Sid);
                    if (!string.IsNullOrWhiteSpace(rawUser) && IsValidUsername(rawUser))
                    {
                        SafeWriteEventLog("Application",
                            $"[DBG-GetMRU] RawEventStore fallback for {computerName}: " +
                            $"user={rawUser} rawTime={best.EventTimeUtc:O}",
                            EventLogEntryType.Information, 2031);
                        return rawUser;
                    }
                }
            }
            catch { /* silent fail */ }

            return null;
        }

        private async Task<bool> TryProcessFallbackLoginFrom6005Async(DateTime eventTime, string computerName, bool writeRawRecord)
        {
            if (!await ShouldAllow6005FallbackAsync(eventTime, computerName))
                return false;

            string? resolvedUsername = null;
            string? fallbackSource = null;
            bool isNetworkUnavailable = false;
            string workDate = eventTime.ToLocalTime().ToString("yyyy-MM-dd");

            lock (knownLoginLock)
            {
                if (lastKnownLoginByComputer.TryGetValue(computerName, out var known) &&
                    known.EventTime.ToLocalTime().ToString("yyyy-MM-dd") == workDate &&
                    IsValidUsername(known.Username))
                {
                    resolvedUsername = known.Username;
                    fallbackSource = "Event6005_PreviousLog";
                }
            }

            if (string.IsNullOrWhiteSpace(resolvedUsername))
            {
                string? fromQueue = await eventQueue.FindMostRecent4624UsernameForComputerAsync(computerName, eventTime);
                if (!string.IsNullOrWhiteSpace(fromQueue) && IsValidUsername(fromQueue))
                {
                    resolvedUsername = fromQueue;
                    fallbackSource = "Event6005_PreviousLog";
                }
            }

            // Fix 4: coba RawEventStore sebelum SharePoint.
            // Kalau Security log bersih dan queue kosong (fresh start), RawEventStore
            // justru punya 4624 valid yang disimpan saat event terjadi — jauh lebih cepat
            // dan lebih akurat daripada query SharePoint raw list.
            if (string.IsNullOrWhiteSpace(resolvedUsername))
            {
                var rawEvents = GetRawEventsFromStore(computerName, eventTime.ToLocalTime().Date, 4624);
                var bestRaw = rawEvents
                    .Where(r => r.EventTimeUtc <= eventTime && IsRelevantLogonType(r.LogonType))
                    .OrderByDescending(r => r.EventTimeUtc)
                    .FirstOrDefault();

                if (bestRaw != null)
                {
                    string? rawUser = bestRaw.Username;
                    if (!string.IsNullOrWhiteSpace(rawUser))
                        rawUser = ResolveUsernameBySid(rawUser, bestRaw.Sid);
                    if (!string.IsNullOrWhiteSpace(rawUser) && IsValidUsername(rawUser))
                    {
                        resolvedUsername = rawUser;
                        fallbackSource = "Event6005_RawStore";
                        SafeWriteEventLog("Application",
                            $"[DBG-6005] Resolved username from RawEventStore for {computerName}: " +
                            $"user={resolvedUsername} rawTime={bestRaw.EventTimeUtc:O}",
                            EventLogEntryType.Information, 2030);
                    }
                }
            }

            if (string.IsNullOrWhiteSpace(resolvedUsername))
            {
                var sharePointLookup = await sharePointIntegration.Value.GetLatestUsernameByComputerWithStatusAsync(computerName, eventTime);
                string? fromSharePoint = sharePointLookup.Username;
                isNetworkUnavailable = sharePointLookup.NetworkUnavailable;
                if (!string.IsNullOrWhiteSpace(fromSharePoint) && IsValidUsername(fromSharePoint))
                {
                    resolvedUsername = fromSharePoint;
                    fallbackSource = "Event6005_SharePoint";
                }
            }

            if (string.IsNullOrWhiteSpace(resolvedUsername))
            {
                await ProcessEvent(
                    6005,
                    "__UNRESOLVED__",
                    eventTime,
                    computerName,
                    "System",
                    0,
                    null,
                    writeRawRecord,
                    usernameResolutionSource: "Fallback6005_Pending",
                    originalUsername: null,
                    fallbackSource: "Event6005_Pending",
                    isFallback: true,
                    resolvedUsername: null,
                    status: "UNCONFIRMED",
                    pendingUsernameResolution: true);

                SafeWriteEventLog("Application",
                    $"[DBG-6005] Fallback login queued as pending at {eventTime:O} on {computerName}. " +
                    $"reason={(isNetworkUnavailable ? "network unavailable" : "username not yet resolvable")}",
                    EventLogEntryType.Information, 2026);
                return true;
            }

            lock (knownLoginLock)
                lastKnownLoginByComputer[computerName] = (resolvedUsername, eventTime);

            await ProcessEvent(
                6005,
                resolvedUsername,
                eventTime,
                computerName,
                "System",
                0,
                null,
                writeRawRecord,
                usernameResolutionSource: "Fallback6005",
                originalUsername: null,
                fallbackSource: fallbackSource,
                isFallback: true,
                resolvedUsername: resolvedUsername,
                status: "UNCONFIRMED",
                pendingUsernameResolution: false);

            return true;
        }

        /// <summary>
        /// Tentukan apakah event 42 (Sleep) boleh dipakai sebagai last-resort ShutdownTime.
        ///
        /// Rules:
        ///   1. Tidak ada event shutdown "lebih baik" di queue untuk user+computer+workDate ini
        ///      (1074, 6006-confirmed, 4647, 6008, 41). Kalau ada, biarkan mereka yang update summary.
        ///   2. Tidak ada wake event (4624/6005) setelah 42 ini di workDate yang sama.
        ///      Kalau ada wake setelah 42 → 42 bukan sleep final → skip.
        ///   3. Username sudah resolved (bukan __UNRESOLVED__).
        ///   4. Timestamp 42 masuk akal: setelah login time (tidak sebelum jam kerja).
        /// </summary>
        private async Task<bool> ShouldUseEvent42AsLastResortAsync(QueuedAttendanceEvent item)
        {
            if (item.EventId != 42)
                return false;

            // Syarat 3: username harus resolved
            if (string.IsNullOrWhiteSpace(item.Username) ||
                item.Username == "__UNRESOLVED__" ||
                !IsValidUsername(item.Username))
                return false;

            // Opt 1: jangan promote 42 terlalu cepat setelah event terjadi.
            // Event 42, 1074, 6006, dan 4647 bisa fire hampir bersamaan (urutan tidak deterministic).
            // Tunggu minimal 15 detik setelah event time agar event shutdown yang lebih baik
            // sempat masuk queue sebelum kita memutuskan 42 adalah last-resort.
            // Kalau belum 15 detik, return false — dispatch loop akan retry event ini nanti.
            if (DateTime.UtcNow - item.EventTime.ToUniversalTime() < TimeSpan.FromSeconds(15))
            {
                SafeWriteEventLog("Application",
                    $"[DBG-42] Too early to promote: elapsed={( DateTime.UtcNow - item.EventTime.ToUniversalTime()).TotalSeconds:F1}s < 15s. " +
                    $"computer={item.ComputerName} user={item.Username}",
                    EventLogEntryType.Information, 2032);
                return false;
            }

            string workDate = item.EventTime.ToLocalTime().ToString("yyyy-MM-dd");

            // Syarat 1: cek apakah ada event shutdown lebih baik di queue
            var allItems = await eventQueue.GetAllAsync();
            bool hasBetterShutdown = allItems.Any(x =>
                x.QueueId != item.QueueId &&
                x.Username.Equals(item.Username, StringComparison.OrdinalIgnoreCase) &&
                x.ComputerName.Equals(item.ComputerName, StringComparison.OrdinalIgnoreCase) &&
                x.EventTime.ToLocalTime().ToString("yyyy-MM-dd") == workDate &&
                (x.EventId == 1074 || x.EventId == 4647 || x.EventId == 6008 || x.EventId == 41 ||
                 (x.EventId == 6006 && !x.EventType.Contains("unconfirmed", StringComparison.OrdinalIgnoreCase))));

            if (hasBetterShutdown)
            {
                SafeWriteEventLog("Application",
                    $"[DBG-42] Skip last-resort: better shutdown event exists in queue. " +
                    $"computer={item.ComputerName} user={item.Username} date={workDate}",
                    EventLogEntryType.Information, 2032);
                return false;
            }

            // Syarat 2: tidak ada wake event setelah 42 ini
            bool hasWakeAfter = await eventQueue.HasWakeEventAfterAsync(
                item.ComputerName, item.EventTime, workDate);
            if (hasWakeAfter)
            {
                SafeWriteEventLog("Application",
                    $"[DBG-42] Skip last-resort: wake event found after sleep at {item.EventTime:O}. " +
                    $"computer={item.ComputerName} user={item.Username}",
                    EventLogEntryType.Information, 2032);
                return false;
            }

            // Syarat 4: cek juga di Security log / RawEventStore apakah ada 4624 setelah 42
            bool hasRawWakeAfter = false;
            try
            {
                var rawAfter = GetRawEventsFromStore(
                    item.ComputerName, item.EventTime.ToLocalTime().Date, 4624);
                hasRawWakeAfter = rawAfter.Any(r => r.EventTimeUtc > item.EventTime);
            }
            catch { /* ignore */ }

            if (hasRawWakeAfter)
            {
                SafeWriteEventLog("Application",
                    $"[DBG-42] Skip last-resort: raw 4624 found after sleep in RawEventStore. " +
                    $"computer={item.ComputerName} user={item.Username} sleepTime={item.EventTime:O}",
                    EventLogEntryType.Information, 2032);
                return false;
            }

            SafeWriteEventLog("Application",
                $"[DBG-42] Promoting to last-resort shutdown: no better event, no wake after. " +
                $"computer={item.ComputerName} user={item.Username} sleepTime={item.EventTime:O}",
                EventLogEntryType.Information, 2032);
            return true;
        }

        private async Task<bool> TryResolvePending6005UsernameAsync(QueuedAttendanceEvent item)
        {
            if (item.EventId != 6005 || !item.PendingUsernameResolution)
                return true;

            string workDate = item.EventTime.ToLocalTime().ToString("yyyy-MM-dd");
            string? resolvedUsername = null;
            string? fallbackSource = null;
            bool networkUnavailable = false;

            var firstAfter = await ResolveFirst4624ForWorkDateAsync(
                item.ComputerName,
                item.EventTime,
                requireAfterEventTime: true);
            if (firstAfter.HasValue && IsValidUsername(firstAfter.Value.Username))
            {
                resolvedUsername = firstAfter.Value.Username;
                fallbackSource = "Event6005_First4624After";
            }

            if (string.IsNullOrWhiteSpace(resolvedUsername))
            {
                var first4624AfterFromQueue = await eventQueue.FindFirst4624ForComputerWorkDateAfterAsync(
                    item.ComputerName,
                    workDate,
                    item.EventTime);
                if (first4624AfterFromQueue.HasValue && IsValidUsername(first4624AfterFromQueue.Value.Username))
                {
                    resolvedUsername = first4624AfterFromQueue.Value.Username;
                    fallbackSource = "Event6005_First4624After";
                }
            }

            if (string.IsNullOrWhiteSpace(resolvedUsername))
            {
                resolvedUsername = await eventQueue.FindMostRecent4624UsernameForComputerAsync(item.ComputerName, item.EventTime);
                if (!string.IsNullOrWhiteSpace(resolvedUsername) && IsValidUsername(resolvedUsername))
                    fallbackSource = "Event6005_PreviousLog";
            }

            if (string.IsNullOrWhiteSpace(resolvedUsername))
            {
                var sharePointLookup = await sharePointIntegration.Value.GetLatestUsernameByComputerWithStatusAsync(
                    item.ComputerName, item.EventTime);
                resolvedUsername = sharePointLookup.Username;
                networkUnavailable = sharePointLookup.NetworkUnavailable;
                if (!string.IsNullOrWhiteSpace(resolvedUsername) && IsValidUsername(resolvedUsername))
                    fallbackSource = "Event6005_SharePoint";
            }

            if (string.IsNullOrWhiteSpace(resolvedUsername))
            {
                item.PendingUsernameResolution = true;
                item.Username = "__UNRESOLVED__";
                item.ResolvedUsername = null;
                item.FallbackSource = "Event6005_Pending";
                item.Status = "UNCONFIRMED";
                item.LastDispatchError = networkUnavailable
                    ? "6005 username unresolved due to network unavailable"
                    : "6005 username unresolved";
                await eventQueue.ReplaceAsync(item);
                return false;
            }

            lock (knownLoginLock)
                lastKnownLoginByComputer[item.ComputerName] = (resolvedUsername, item.EventTime);

            item.Username = resolvedUsername;
            item.ResolvedUsername = resolvedUsername;
            item.IsFallback = true;
            item.UsernameResolutionSource = "Fallback6005";
            item.FallbackSource = fallbackSource;
            item.Status = "UNCONFIRMED";
            item.PendingUsernameResolution = false;
            item.LastDispatchError = null;
            await eventQueue.ReplaceAsync(item);

            // FIX [BUG-5]: Propagate username ke firstLogon4624 index agar event
            // berikutnya (1074/6006) bisa resolve username via ResolveFirst4624UsernameForWorkDateAsync.
            RegisterFirst4624Logon(item.ComputerName, resolvedUsername, item.EventTime);

            return true;
        }

        private async Task<bool> TryResolvePendingSystemUsernameAsync(QueuedAttendanceEvent item)
        {
            if (!item.PendingUsernameResolution)
                return true;

            if (!SupportsPendingSystemResolution(item.EventId))
                return true;

            string? resolvedUsername = null;
            string? fallbackSource = null;
            bool networkUnavailable = false;

            var first4624 = await ResolveFirst4624ForWorkDateAsync(
                item.ComputerName,
                item.EventTime,
                requireAfterEventTime: false);
            if (first4624.HasValue && IsValidUsername(first4624.Value.Username))
            {
                resolvedUsername = first4624.Value.Username;
                fallbackSource = $"Event{item.EventId}_First4624";
            }

            if (string.IsNullOrWhiteSpace(resolvedUsername))
            {
                var fromQueue = await eventQueue.FindMostRecent4624UsernameForComputerAsync(item.ComputerName, item.EventTime);
                if (!string.IsNullOrWhiteSpace(fromQueue) && IsValidUsername(fromQueue))
                {
                    resolvedUsername = fromQueue;
                    fallbackSource = $"Event{item.EventId}_Queue4624";
                }
            }

            if (string.IsNullOrWhiteSpace(resolvedUsername))
            {
                var sharePointLookup = await sharePointIntegration.Value.GetLatestUsernameByComputerWithStatusAsync(
                    item.ComputerName, item.EventTime);
                string? fromSharePoint = sharePointLookup.Username;
                networkUnavailable = sharePointLookup.NetworkUnavailable;
                if (!string.IsNullOrWhiteSpace(fromSharePoint) && IsValidUsername(fromSharePoint))
                {
                    resolvedUsername = fromSharePoint;
                    fallbackSource = $"Event{item.EventId}_SharePoint";
                }
            }

            if (string.IsNullOrWhiteSpace(resolvedUsername))
            {
                item.PendingUsernameResolution = true;
                item.Username = "__UNRESOLVED__";
                item.ResolvedUsername = null;
                item.IsFallback = true;
                item.UsernameResolutionSource = "FallbackSystem_Pending";
                item.FallbackSource = BuildPendingFallbackSource(item.EventId);
                item.Status = "UNCONFIRMED";
                item.LastDispatchError = networkUnavailable
                    ? $"{item.EventId} username unresolved due to network unavailable"
                    : $"{item.EventId} username unresolved";
                await eventQueue.ReplaceAsync(item);
                return false;
            }

            lock (knownLoginLock)
                lastKnownLoginByComputer[item.ComputerName] = (resolvedUsername, item.EventTime);

            item.Username = resolvedUsername;
            item.ResolvedUsername = resolvedUsername;
            item.IsFallback = true;
            item.UsernameResolutionSource = "FallbackSystemResolved";
            item.FallbackSource = fallbackSource;
            item.Status = "UNCONFIRMED";
            item.PendingUsernameResolution = false;
            item.LastDispatchError = null;
            await eventQueue.ReplaceAsync(item);
            return true;
        }

        private async Task<bool> ShouldAllow6005FallbackAsync(DateTime eventTime, string computerName)
        {
            if (replayInProgress)
                return false;

            string workDate = eventTime.ToLocalTime().ToString("yyyy-MM-dd");
            var first4624 = await ResolveFirst4624ForWorkDateAsync(
                computerName,
                eventTime,
                requireAfterEventTime: false);

            if (first4624.HasValue)
            {
                if (TryGetStartupAnchorForWorkDate(computerName, eventTime, out DateTime startupAnchorUtc))
                {
                    TimeSpan gap = first4624.Value.EventTime - startupAnchorUtc;
                    if (gap < TimeSpan.Zero)
                    {
                        SafeWriteEventLog("Application",
                            $"[DBG-6005] Startup anchor is later than first 4624. " +
                            $"computer={computerName} workDate={workDate} startup={startupAnchorUtc:O} " +
                            $"first4624={first4624.Value.EventTime:O}",
                            EventLogEntryType.Warning, 2032);
                        gap = TimeSpan.Zero;
                    }

                    if (gap <= startupToFirst4624MaxGapForDirectUse)
                    {
                        SafeWriteEventLog("Application",
                            $"[DBG-6005] SKIP fallback: startup→first4624 gap within threshold. " +
                            $"computer={computerName} workDate={workDate} startup={startupAnchorUtc:O} " +
                            $"first4624={first4624.Value.EventTime:O} gapMin={gap.TotalMinutes:F1} " +
                            $"thresholdMin={startupToFirst4624MaxGapForDirectUse.TotalMinutes:F1}",
                            EventLogEntryType.Information, 2024);
                        return false;
                    }

                    SafeWriteEventLog("Application",
                        $"[DBG-6005] ALLOW fallback: startup→first4624 gap exceeds threshold. " +
                        $"computer={computerName} workDate={workDate} startup={startupAnchorUtc:O} " +
                        $"first4624={first4624.Value.EventTime:O} gapMin={gap.TotalMinutes:F1} " +
                        $"thresholdMin={startupToFirst4624MaxGapForDirectUse.TotalMinutes:F1}",
                        EventLogEntryType.Information, 2025);
                    return true;
                }

                SafeWriteEventLog("Application",
                    $"[DBG-6005] SKIP fallback: first 4624 already available and startup anchor not found. " +
                    $"computer={computerName} workDate={workDate} first4624={first4624.Value.EventTime:O}",
                    EventLogEntryType.Information, 2027);
                return false;
            }

            return IsSecurityLogUnavailableOrLikelyCleared(eventTime, computerName);
        }

        private bool IsSecurityLogUnavailableOrLikelyCleared(DateTime eventTime, string computerName)
        {
            try
            {
                EventLog secLog = securityEventLog ?? new EventLog("Security");
                int total = secLog.Entries.Count;
                if (total == 0)
                    return true;

                DateTime workDateStartLocal = eventTime.ToLocalTime().Date;
                DateTime workDateStartUtc = workDateStartLocal.ToUniversalTime();
                DateTime oldestSeen = DateTime.MaxValue;
                bool has4624Today = false;
                bool hasLogClearedSignal = false;
                int scanned = 0;

                for (int i = total - 1; i >= 0 && scanned < 4000; i--)
                {
                    scanned++;
                    EventLogEntry entry = secLog.Entries[i];
                    DateTime t = entry.TimeGenerated.ToUniversalTime();
                    if (t < oldestSeen)
                        oldestSeen = t;

                    if (t < workDateStartUtc)
                        break;

                    int eventId = GetNormalizedEventId(entry);
                    if (eventId == 1102)
                        hasLogClearedSignal = true;

                    if (eventId == 4624 && entry.MachineName.Equals(computerName, StringComparison.OrdinalIgnoreCase))
                    {
                        int lt = ParseLogonType(entry.Message ?? string.Empty);
                        if (IsRelevantLogonType(lt))
                        {
                            has4624Today = true;
                            break;
                        }
                    }
                }

                if (has4624Today)
                    return false;

                if (hasLogClearedSignal)
                    return true;

                // FIX [BUG-4]: Kalau tidak ada 4624 hari ini di Security log tapi ada event lain
                // hari ini (oldestSeen masih hari ini), cek RawEventStore sebagai tiebreaker.
                // Kasus ini terjadi saat log rotation membuang 4624 pagi tapi entry lain masih ada.
                // Kalau RawEventStore punya 4624 hari ini → log cleared/rotated → allow fallback.
                if (oldestSeen <= workDateStartUtc)
                {
                    // oldestSeen sebelum workDate → log punya history hari ini, 4624 memang tidak ada
                    return false;
                }

                // oldestSeen setelah workDate start → log tidak punya entry dari awal hari ini.
                // Cek RawEventStore: kalau ada 4624 tersimpan di sana, berarti log cleared.
                var rawToday = GetRawEventsFromStore(computerName, workDateStartLocal, 4624);
                if (rawToday.Count > 0)
                {
                    SafeWriteEventLog("Application",
                        $"[DBG-6005] RawEventStore has {rawToday.Count} 4624 for {computerName} " +
                        $"on {workDateStartLocal:yyyy-MM-dd} but Security log missing → treating as cleared.",
                        EventLogEntryType.Information, 2027);
                    return true;
                }

                return oldestSeen > workDateStartUtc;
            }
            catch
            {
                return true;
            }
        }

        private async Task<string?> ResolveFirst4624UsernameForWorkDateAsync(string computerName, DateTime eventTime)
        {
            var first = await ResolveFirst4624ForWorkDateAsync(
                computerName,
                eventTime,
                requireAfterEventTime: false);
            return first?.Username;
        }

        private async Task<(string Username, DateTime EventTime)?> ResolveFirst4624ForWorkDateAsync(
            string computerName,
            DateTime eventTime,
            bool requireAfterEventTime)
        {
            string workDate = eventTime.ToLocalTime().ToString("yyyy-MM-dd");
            string key = BuildDeviceWorkDateKey(computerName, workDate);

            lock (firstLogonLock)
            {
                if (firstLogon4624ByDeviceWorkDate.TryGetValue(key, out var fromMemory) &&
                    !string.IsNullOrWhiteSpace(fromMemory.Username) &&
                    IsValidUsername(fromMemory.Username) &&
                    (!requireAfterEventTime || fromMemory.EventTime >= eventTime))
                    return fromMemory;
            }

            var firstFromQueue = requireAfterEventTime
                ? await eventQueue.FindFirst4624ForComputerWorkDateAfterAsync(computerName, workDate, eventTime)
                : await eventQueue.FindFirst4624ForComputerWorkDateAsync(computerName, workDate);
            if (firstFromQueue.HasValue && IsValidUsername(firstFromQueue.Value.Username))
            {
                lock (firstLogonLock)
                {
                    if (!firstLogon4624ByDeviceWorkDate.TryGetValue(key, out var existing) ||
                        firstFromQueue.Value.EventTime < existing.EventTime)
                        firstLogon4624ByDeviceWorkDate[key] = firstFromQueue.Value;
                }
                return firstFromQueue.Value;
            }

            try
            {
                EventLog? ownedSecLog = null;
                EventLog secLog = securityEventLog ?? (ownedSecLog = new EventLog("Security"));
                try
                {
                    int total = secLog.Entries.Count;
                    if (total == 0)
                        return null;

                    DateTime dayStartUtc = eventTime.ToLocalTime().Date.ToUniversalTime();
                    DateTime dayEndUtc = dayStartUtc.AddDays(1);
                    (string Username, DateTime EventTime)? best = null;

                    for (int i = total - 1; i >= 0; i--)
                    {
                        EventLogEntry entry = secLog.Entries[i];
                        if (!entry.MachineName.Equals(computerName, StringComparison.OrdinalIgnoreCase))
                            continue;

                        DateTime t = entry.TimeGenerated.ToUniversalTime();
                        if (t < dayStartUtc)
                            break;
                        if (t >= dayEndUtc)
                            continue;
                        if (requireAfterEventTime && t < eventTime)
                            continue;

                        if (GetNormalizedEventId(entry) != 4624)
                            continue;

                        string message = entry.Message ?? string.Empty;
                        int lt = ParseLogonType(message);
                        if (!IsRelevantLogonType(lt) || IsAdminSplitTokenLogin(message))
                            continue;

                        string? username = GetUsernameFromEvent(message, 4624);
                        if (string.IsNullOrWhiteSpace(username))
                            continue;

                        string? sid = GetUserSidFromSecurityEvent(message, 4624);
                        username = ResolveUsernameBySid(username, sid);
                        if (!IsValidUsername(username))
                            continue;

                        if (!best.HasValue || t < best.Value.EventTime)
                            best = (username, t);
                    }

                    if (best.HasValue)
                    {
                        lock (firstLogonLock)
                        {
                            if (!firstLogon4624ByDeviceWorkDate.TryGetValue(key, out var existing) ||
                                best.Value.EventTime < existing.EventTime)
                                firstLogon4624ByDeviceWorkDate[key] = best.Value;
                        }
                    }

                    // Opsi 3 fallback: selalu bandingkan dengan RawEventStore, tidak hanya kalau
                    // Security log kosong. Kasus partial rotation: 4624 jam 08:00 sudah ter-rotate
                    // tapi 4624 jam 11:00 masih ada → best dari Security log = 11:00, padahal
                    // RawEventStore masih punya yang 08:00. Tanpa perbandingan ini, login pertama
                    // yang benar (08:00) tidak pernah terpilih.
                    {
                        var rawEvents = GetRawEventsFromStore(computerName, eventTime.ToLocalTime().Date, 4624);
                        bool rawImproved = false;
                        foreach (var raw in rawEvents)
                        {
                            if (requireAfterEventTime && raw.EventTimeUtc < eventTime)
                                continue;
                            if (!IsRelevantLogonType(raw.LogonType))
                                continue;

                            string? rawUser = raw.Username;
                            if (!string.IsNullOrWhiteSpace(rawUser))
                                rawUser = ResolveUsernameBySid(rawUser, raw.Sid);
                            if (string.IsNullOrWhiteSpace(rawUser) || !IsValidUsername(rawUser))
                                continue;

                            // Ambil kalau lebih awal dari best saat ini (dari Security log maupun sebelumnya)
                            if (!best.HasValue || raw.EventTimeUtc < best.Value.EventTime)
                            {
                                best = (rawUser, raw.EventTimeUtc);
                                rawImproved = true;
                            }
                        }

                        if (rawImproved && best.HasValue)
                        {
                            SafeWriteEventLog("Application",
                                $"[DBG-4624] RawEventStore found earlier first 4624 for {computerName}: " +
                                $"user={best.Value.Username} time={best.Value.EventTime:O}",
                                EventLogEntryType.Information, 2028);
                            lock (firstLogonLock)
                            {
                                if (!firstLogon4624ByDeviceWorkDate.TryGetValue(key, out var existing) ||
                                    best.Value.EventTime < existing.EventTime)
                                    firstLogon4624ByDeviceWorkDate[key] = best.Value;
                            }
                        }
                    }

                    return best;
                }
                finally
                {
                    ownedSecLog?.Dispose();
                }
            }
            catch (Exception ex)
            {
                SafeWriteEventLog("Application",
                    $"[DBG-4624] Failed to resolve first 4624 for {computerName} at {eventTime:O}: {ex.Message}",
                    EventLogEntryType.Warning, 2028);
                return null;
            }
        }

        private bool TryGetStartupAnchorForWorkDate(string computerName, DateTime eventTime, out DateTime startupAnchorUtc)
        {
            string workDate = eventTime.ToLocalTime().ToString("yyyy-MM-dd");
            string key = BuildDeviceWorkDateKey(computerName, workDate);

            lock (startupAnchorLock)
            {
                if (startupAnchorByDeviceWorkDate.TryGetValue(key, out startupAnchorUtc))
                    return true;
            }

            if (TryScanStartupAnchorForWorkDate(computerName, eventTime, out startupAnchorUtc))
            {
                lock (startupAnchorLock)
                    startupAnchorByDeviceWorkDate[key] = startupAnchorUtc;
                return true;
            }

            startupAnchorUtc = default;
            return false;
        }

        private bool TryScanStartupAnchorForWorkDate(string computerName, DateTime eventTime, out DateTime startupAnchorUtc)
        {
            startupAnchorUtc = default;
            try
            {
                EventLog? ownedSysLog = null;
                EventLog sysLog = systemEventLog ?? (ownedSysLog = new EventLog("System"));
                try
                {
                    int total = sysLog.Entries.Count;
                    if (total == 0)
                        return false;

                    DateTime dayStartUtc = eventTime.ToLocalTime().Date.ToUniversalTime();
                    DateTime dayEndUtc = dayStartUtc.AddDays(1);
                    DateTime? earliest = null;

                    for (int i = total - 1; i >= 0; i--)
                    {
                        EventLogEntry entry = sysLog.Entries[i];
                        if (!entry.MachineName.Equals(computerName, StringComparison.OrdinalIgnoreCase))
                            continue;

                        DateTime t = entry.TimeGenerated.ToUniversalTime();
                        if (t < dayStartUtc)
                            break;
                        if (t >= dayEndUtc)
                            continue;

                        int eventId = GetNormalizedEventId(entry);
                        if (!IsStartupAnchorEventId(eventId))
                            continue;

                        if (!earliest.HasValue || t < earliest.Value)
                            earliest = t;
                    }

                    if (!earliest.HasValue)
                        return false;

                    startupAnchorUtc = earliest.Value;
                    return true;
                }
                finally
                {
                    ownedSysLog?.Dispose();
                }
            }
            catch (Exception ex)
            {
                SafeWriteEventLog("Application",
                    $"[DBG-6005] Failed to scan startup anchor for {computerName} at {eventTime:O}: {ex.Message}",
                    EventLogEntryType.Warning, 2029);
                return false;
            }
        }

        private static bool IsStartupAnchorEventId(int eventId)
            => eventId == 12 || eventId == 6005 || eventId == 6009;

        private void RegisterFirst4624Logon(string computerName, string username, DateTime eventTime)
        {
            string workDate = eventTime.ToLocalTime().ToString("yyyy-MM-dd");
            string key = BuildDeviceWorkDateKey(computerName, workDate);

            lock (firstLogonLock)
            {
                // Track earliest login (existing behavior)
                if (!firstLogon4624ByDeviceWorkDate.TryGetValue(key, out var existing) ||
                    eventTime < existing.EventTime)
                {
                    firstLogon4624ByDeviceWorkDate[key] = (username, eventTime);
                }

                // Track semua login untuk isNewSession check di shutdown dispatch
                if (!allLogon4624ByDeviceWorkDate.TryGetValue(key, out var logins))
                {
                    logins = new List<DateTime>();
                    allLogon4624ByDeviceWorkDate[key] = logins;
                }
                if (!logins.Contains(eventTime))
                    logins.Add(eventTime);
            }
        }

        private async Task PrimeFirstLogonIndexFromQueueAsync(CancellationToken cancellationToken)
        {
            try
            {
                List<QueuedAttendanceEvent> items = await eventQueue.GetAllAsync(cancellationToken);
                foreach (var item in items)
                {
                    if (item.EventId != 4624 || string.IsNullOrWhiteSpace(item.Username) || !IsValidUsername(item.Username))
                        continue;

                    RegisterFirst4624Logon(item.ComputerName, item.Username, item.EventTime);
                }
            }
            catch (Exception ex)
            {
                SafeWriteEventLog("Application",
                    $"[STARTUP] Failed to prime first-4624 index from queue: {ex.Message}",
                    EventLogEntryType.Warning, 1045);
            }
        }

        private static string BuildDeviceWorkDateKey(string computerName, string workDate)
            => $"{computerName}::{workDate}";

        private string? GetUserSidFromSecurityEvent(string message, int securityEventId)
        {
            try
            {
                // Security event only: 4624 (New Logon) and 4647 (Subject).
                string anchor = securityEventId == 4624 ? "New Logon:" :
                                securityEventId == 4647 ? "Subject:" : string.Empty;
                if (string.IsNullOrEmpty(anchor))
                    return null;

                int anchorIndex = message.IndexOf(anchor, StringComparison.OrdinalIgnoreCase);
                if (anchorIndex == -1)
                    return null;

                var regex = new Regex(@"Security ID:\s*([^\r\n]+)", RegexOptions.IgnoreCase);
                var match = regex.Match(message, anchorIndex);
                if (!match.Success)
                    return null;

                string sid = match.Groups[1].Value.Trim();
                if (string.IsNullOrWhiteSpace(sid) ||
                    sid.Equals("-", StringComparison.OrdinalIgnoreCase) ||
                    sid.Equals("NULL SID", StringComparison.OrdinalIgnoreCase))
                    return null;

                return sid.StartsWith("S-", StringComparison.OrdinalIgnoreCase) ? sid : null;
            }
            catch { /* silent fail */ }

            return null;
        }

        private string ResolveUsernameBySid(string username, string? sid)
        {
            string fallback = NormalizeDisplayUsername(username);
            if (string.IsNullOrWhiteSpace(sid))
                return fallback;

            lock (sidCacheLock)
            {
                if (sidUsernameCache.TryGetValue(sid, out string? cached) && IsValidUsername(cached))
                    return cached;
            }

            try
            {
                var securityId = new SecurityIdentifier(sid);
                var ntAccount = securityId.Translate(typeof(NTAccount)) as NTAccount;
                string translated = NormalizeDisplayUsername(ntAccount?.Value ?? string.Empty);

                if (IsValidUsername(translated))
                {
                    lock (sidCacheLock)
                        sidUsernameCache[sid] = translated;
                    return translated;
                }
            }
            catch { /* fallback to parsed account name */ }

            return fallback;
        }

        private static string NormalizeDisplayUsername(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
                return string.Empty;

            string normalized = username.Trim();

            if (normalized.Contains("\\"))
            {
                int slashIndex = normalized.LastIndexOf('\\');
                normalized = normalized.Substring(slashIndex + 1).Trim();
            }

            if (normalized.Contains("@"))
                normalized = normalized.Split('@')[0].Trim();

            return normalized;
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
                // Cari anchor "on behalf of user" (English) atau variannya (non-English).
                // Semua pattern harus beroperasi SETELAH anchor ini — bukan scan seluruh message —
                // agar tidak tersangkut path executable di baris pertama seperti:
                //   "C:\WINDOWS\servicing\TrustedInstaller.exe ... on behalf of user NT AUTHORITY\SYSTEM"
                // yang menyebabkan Pattern 3 match "servicing", "system32", "uus", dll. sebagai username.

                // Pattern 1 (English): "on behalf of user DOMAIN\User for the following reason"
                var match = Regex.Match(message, @"on behalf of user\s+([^\r\n]+)", RegexOptions.IgnoreCase);

                // Pattern 2 (non-English / Indonesian): "atas nama pengguna DOMAIN\User untuk alasan"
                if (!match.Success)
                    match = Regex.Match(message,
                        @"(?:atas nama pengguna|au nom de l'utilisateur|im Auftrag des Benutzers|en nombre del usuario)\s+([^\r\n]+)",
                        RegexOptions.IgnoreCase);

                if (match.Success)
                {
                    string candidate = match.Groups[1].Value.Trim();

                    // Buang trailing "for the following reason" / "untuk alasan berikut" dll.
                    var trailingPattern = new Regex(
                        @"\s+(?:for the following reason|untuk alasan berikut|pour la raison suivante|aus folgendem Grund|por la siguiente raz[oó]n).*$",
                        RegexOptions.IgnoreCase);
                    candidate = trailingPattern.Replace(candidate, string.Empty).Trim();

                    candidate = NormalizeDisplayUsername(candidate);

                    if (IsValidUsername(candidate))
                        return candidate;

                    // Username dari anchor tidak valid (misal SYSTEM, TrustedInstaller) →
                    // langsung return null, biarkan caller lakukan fallback ke 4624/queue.
                    // Jangan lanjut ke Pattern 3 karena anchor sudah ditemukan tapi usernya sistem.
                    SafeWriteEventLog("Application",
                        $"[DBG-1074] GetUserFromSystem1074Message: anchor found but username '{candidate}' is system/invalid → fallback to 4624",
                        EventLogEntryType.Information, 2020);
                    return null;
                }

                // Pattern 3 (broad fallback untuk locale tidak dikenal).
                // DIBATASI: hanya scan dari posisi setelah tanda titik pertama di baris kedua ke bawah,
                // bukan dari awal message, agar tidak tersangkut path exe di baris pertama.
                // Strategi: cari baris yang mengandung "DOMAIN\User" tapi bukan path file (tidak ada :\).
                foreach (string line in message.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    // Skip baris yang merupakan path file (ada drive letter seperti C:\)
                    if (Regex.IsMatch(line, @"[A-Za-z]:\\", RegexOptions.None))
                        continue;

                    var domainMatch = Regex.Match(line, @"[A-Za-z0-9_\-]+\\([A-Za-z0-9_\.\-]+)", RegexOptions.IgnoreCase);
                    if (domainMatch.Success)
                    {
                        string candidate = domainMatch.Groups[1].Value.Trim();
                        if (IsValidUsername(candidate))
                        {
                            SafeWriteEventLog("Application",
                                $"[DBG-1074] GetUserFromSystem1074Message: Pattern 3 fallback matched '{candidate}' from line: '{line.Trim()}'",
                                EventLogEntryType.Information, 2020);
                            return candidate;
                        }
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
                last1074States.Add(new Last1074State(username, eventTime, shutdownType));

                DateTime pruneBefore = eventTime - last1074RetentionWindow;
                last1074States.RemoveAll(x => x.EventTime < pruneBefore);
            }
        }

        /// <summary>
        /// Tries to find a 1074 event before the given 6006 event time.
        /// Priority: <=60s window first. Fallback: >60s and <=120s only when primary fails.
        /// Returns (username, shutdownType) if a matching 1074 exists, or (null, null) if not.
        /// shutdownType will be null if the paired 1074 was a Restart (not a real power-off).
        /// </summary>
        private (string? Username, string? ShutdownType) TryResolve1074StateFor6006(DateTime eventTime)
        {
            lock (last1074Lock)
            {
                if (last1074States.Count == 0)
                {
                    SafeWriteEventLog("Application",
                        $"[DBG-6006] TryResolve: no prior 1074 state in memory.",
                        EventLogEntryType.Information, 2010);
                    return (null, null);
                }

                Last1074State? primaryCandidate = null;
                Last1074State? fallbackCandidate = null;
                double primaryDiffSeconds = double.MaxValue;
                double fallbackDiffSeconds = double.MaxValue;

                for (int i = 0; i < last1074States.Count; i++)
                {
                    Last1074State candidate = last1074States[i];
                    if (candidate.EventTime > eventTime)
                        continue;

                    double diffSeconds = (eventTime - candidate.EventTime).TotalSeconds;
                    if (diffSeconds <= primary1074PairWindow.TotalSeconds)
                    {
                        if (primaryCandidate == null || candidate.EventTime > primaryCandidate.EventTime)
                        {
                            primaryCandidate = candidate;
                            primaryDiffSeconds = diffSeconds;
                        }
                    }
                    else if (diffSeconds <= fallback1074PairWindow.TotalSeconds)
                    {
                        if (fallbackCandidate == null || candidate.EventTime > fallbackCandidate.EventTime)
                        {
                            fallbackCandidate = candidate;
                            fallbackDiffSeconds = diffSeconds;
                        }
                    }
                }

                if (primaryCandidate != null)
                {
                    bool isRestartPrimary = IsRestartShutdownType(primaryCandidate.ShutdownType);
                    string? confirmedPrimaryShutdownType = isRestartPrimary ? null : primaryCandidate.ShutdownType;

                    SafeWriteEventLog("Application",
                        $"[DBG-6006] TryResolve: matched PRIMARY<=60s username='{primaryCandidate.Username}' " +
                        $"diff={primaryDiffSeconds:F1}s 1074Type='{primaryCandidate.ShutdownType}' isRestart={isRestartPrimary}",
                        EventLogEntryType.Information, 2012);

                    return (primaryCandidate.Username, confirmedPrimaryShutdownType);
                }

                if (fallbackCandidate == null)
                {
                    SafeWriteEventLog("Application",
                        $"[DBG-6006] TryResolve: no 1074 candidate in <=120s window before 6006. 6006Time={eventTime:O}",
                        EventLogEntryType.Information, 2011);
                    return (null, null);
                }

                SafeWriteEventLog("Application",
                    $"[DBG-6006] TryResolve: PRIMARY<=60s missed, evaluating FALLBACK60-120s " +
                    $"latestCandidate username='{fallbackCandidate.Username}' candidateTime={fallbackCandidate.EventTime:O} " +
                    $"6006Time={eventTime:O}",
                    EventLogEntryType.Information, 2011);

                bool restartIndicationInFallbackRange = false;
                for (int i = 0; i < last1074States.Count; i++)
                {
                    Last1074State candidate = last1074States[i];
                    // Only inspect 1074 states that happened from the selected fallback candidate
                    // up to this 6006 event; any restart in this interval invalidates fallback pairing.
                    if (candidate.EventTime < fallbackCandidate.EventTime || candidate.EventTime > eventTime)
                        continue;

                    if (IsRestartShutdownType(candidate.ShutdownType))
                    {
                        restartIndicationInFallbackRange = true;
                        break;
                    }
                }

                if (restartIndicationInFallbackRange)
                {
                    SafeWriteEventLog("Application",
                        $"[DBG-6006] TryResolve: FALLBACK60-120s used=false (restart indication found). " +
                        $"candidateTime={fallbackCandidate.EventTime:O} 6006Time={eventTime:O}",
                        EventLogEntryType.Information, 2011);
                    return (null, null);
                }

                SafeWriteEventLog("Application",
                    $"[DBG-6006] TryResolve: FALLBACK60-120s used=true username='{fallbackCandidate.Username}' " +
                    $"diff={fallbackDiffSeconds:F1}s 1074Type='{fallbackCandidate.ShutdownType}' " +
                    $"(PRIMARY<=60s had no match)",
                    EventLogEntryType.Information, 2012);

                bool isRestartFallback = IsRestartShutdownType(fallbackCandidate.ShutdownType);
                string? confirmedFallbackShutdownType = isRestartFallback ? null : fallbackCandidate.ShutdownType;
                return (fallbackCandidate.Username, confirmedFallbackShutdownType);
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

        private bool IsSystemFallbackTriggerAccount(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
                return true;

            string normalized = username.Trim();
            if (systemFallbackTriggerAccounts.Contains(normalized))
                return true;

            for (int i = 0; i < systemFallbackTriggerContains.Count; i++)
            {
                string token = systemFallbackTriggerContains[i];
                if (!string.IsNullOrWhiteSpace(token) &&
                    normalized.Contains(token, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }

        private static bool SupportsPendingSystemResolution(int eventId)
        {
            return eventId == 1074 || eventId == 6006 || eventId == 4647 ||
                   eventId == 42 || eventId == 6008 || eventId == 41;
        }

        private static string BuildPendingFallbackSource(int eventId)
            => $"Event{eventId}_Pending";

        private static readonly HashSet<string> _invalidUsernames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            // Akun sistem Windows standar
            "SYSTEM", "LOCAL SERVICE", "LOCAL_SYSTEM", "NETWORK SERVICE",
            "ANONYMOUS LOGON", "Guest", "DefaultAccount", "Administrator",
            // Nama Windows path component yang terbukti lolos lewat Pattern 3
            // karena ada di path executable di baris pertama event 1074
            // (misal C:\WINDOWS\servicing\TrustedInstaller.exe → "servicing")
            "system32", "syswow64", "servicing", "winsxs", "uus",
            "trustedinstaller", "svchost", "services", "lsass", "winlogon",
            "explorer", "consent", "credpro"
        };

        private static readonly string[] _invalidUsernamePrefixes =
        {
            "DWM-", "UMFD-", "NT Service",
            // Path-relative prefixes yang kadang tersisa setelah NormalizeDisplayUsername
            "NT AUTHORITY", "BUILTIN"
        };

        // #3: IsValidUsername static — _invalidUsernames dan _invalidUsernamePrefixes sudah
        // static readonly, method-nya juga harus static agar tidak ada implicit instance capture.
        private static bool IsValidUsername(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
                return false;

            if (_invalidUsernames.Contains(username)) return false;
            if (username.EndsWith("$")) return false;

            foreach (var prefix in _invalidUsernamePrefixes)
                if (username.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    return false;

            return true;
        }
    }
}