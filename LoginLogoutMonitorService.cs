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
        // Retention diperpanjang ke 10 menit (sebelumnya 5 menit) untuk menangkap kasus
        // PC sangat lambat shutdown — jarak antara 1074 dan 6006 bisa >5 menit.
        // Forward search (inverted order) di TryResolve1074StateFor6006 juga butuh state ini
        // masih ada di memory saat 6006 tiba belakangan.
        private static readonly TimeSpan last1074RetentionWindow = TimeSpan.FromMinutes(10);
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

        // ── Admin session correlation service ────────────────────────────────────
        private readonly AdminSessionCorrelationService _adminCorrelationService;

        private int queueAlertThreshold = 500;
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
            _adminCorrelationService = new AdminSessionCorrelationService(rawEventStore, WriteAdminCorrelationLog);

            // Allow OnShutdown() to be called during system shutdown/restart.
            // Without this, ServiceBase never invokes OnShutdown() and the checkpoint is lost.
            CanShutdown = true;

            // GAP FIX [POWER]: Terima notifikasi resume dari SCM saat PC keluar dari
            // hibernate / suspend. Tanpa ini, OnPowerEvent tidak pernah dipanggil dan
            // subscription drop pasca-resume baru dideteksi oleh startup probe 90 detik —
            // ada window buta di mana 4624 login setelah wake tidak tertangkap.
            CanHandlePowerEvent = true;

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

            // Catat kapan subscription diaktifkan — startup probe butuh referensi ini
            // untuk menghitung berapa lama subscription sudah aktif tanpa menerima event.
            Interlocked.Exchange(ref _subscriptionEnabledTicksUtc, DateTime.UtcNow.Ticks);
            Interlocked.Exchange(ref _systemSubscriptionEnabledTicksUtc, DateTime.UtcNow.Ticks);

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

                            // Self-healing: pastikan startup type tetap Automatic dan
                            // sc failure recovery action tetap terkonfigurasi.
                            // Dijalankan setiap service start agar Windows Update atau
                            // Group Policy yang me-reset konfigurasi ini langsung diperbaiki.
                            EnsureServiceResilience();

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

        // ─── Self-healing: startup type + sc failure ─────────────────────────────

        /// <summary>
        /// Dipanggil setiap service start dari background startup thread.
        /// Tujuan: memastikan dua konfigurasi kritis tidak pernah hilang:
        ///   1. StartupType = Automatic — Windows Update / Group Policy kadang me-reset ke Manual.
        ///   2. sc failure recovery actions — ter-reset setelah Windows Feature Update.
        ///
        /// Kedua operasi pakai Process.Start("sc.exe") karena .NET ServiceController
        /// tidak expose SetStartMode dan tidak bisa set failure actions.
        /// Kalau sc.exe gagal (misal akses ditolak), error di-log tapi tidak throw —
        /// service tetap jalan normal, hanya self-healing yang tidak berhasil.
        ///
        /// Tidak perlu elevated check di sini karena service Windows selalu jalan
        /// sebagai LocalSystem atau akun yang punya hak modify service config.
        /// </summary>
        private void EnsureServiceResilience()
        {
            try
            {
                string serviceName = ServiceName; // nama service dari SCM, set oleh installer
                if (string.IsNullOrWhiteSpace(serviceName))
                {
                    SafeWriteEventLog("Application",
                        "[RESILIENCE] ServiceName kosong — skip self-healing.",
                        EventLogEntryType.Warning, 1060);
                    return;
                }

                EnsureStartupTypeAutomatic(serviceName);
                EnsureFailureActions(serviceName);
            }
            catch (Exception ex)
            {
                // Tidak boleh throw — self-healing gagal tidak boleh crash service.
                SafeWriteEventLog("Application",
                    $"[RESILIENCE] EnsureServiceResilience error: {ex.Message}",
                    EventLogEntryType.Warning, 1060);
            }
        }

        /// <summary>
        /// Cek startup type lewat sc.exe qc, perbaiki ke auto kalau bukan auto.
        /// sc.exe qc output: "START_TYPE: 2 AUTO_START" atau "3 DEMAND_START" (manual), dll.
        /// </summary>
        private void EnsureStartupTypeAutomatic(string serviceName)
        {
            try
            {
                // Query current start type
                string qcOutput = RunSc($"qc \"{serviceName}\"");

                // "2   AUTO_START"  → sudah auto, tidak perlu apa-apa
                // "2   AUTO_START  (DELAYED)" → auto delayed, juga acceptable
                bool isAlreadyAuto = qcOutput.Contains("AUTO_START", StringComparison.OrdinalIgnoreCase);
                if (isAlreadyAuto)
                {
                    SafeWriteEventLog("Application",
                        $"[RESILIENCE] StartupType sudah AUTO — tidak perlu perubahan.",
                        EventLogEntryType.Information, 1061);
                    return;
                }

                // Bukan auto (manual/disabled) → perbaiki
                SafeWriteEventLog("Application",
                    $"[RESILIENCE] StartupType bukan AUTO (output: '{qcOutput.Trim()}') — " +
                    $"memperbaiki ke auto...",
                    EventLogEntryType.Warning, 1062);

                string configOutput = RunSc($"config \"{serviceName}\" start= auto");

                SafeWriteEventLog("Application",
                    $"[RESILIENCE] StartupType diperbaiki ke AUTO. sc config output: '{configOutput.Trim()}'",
                    EventLogEntryType.Information, 1063);
            }
            catch (Exception ex)
            {
                SafeWriteEventLog("Application",
                    $"[RESILIENCE] EnsureStartupTypeAutomatic error: {ex.Message}",
                    EventLogEntryType.Warning, 1064);
            }
        }

        /// <summary>
        /// Cek apakah sc failure sudah terkonfigurasi lewat sc.exe qfailure.
        /// Kalau belum ada recovery action (reset= 0, actions kosong), set ulang.
        ///
        /// Target config:
        ///   reset= 86400 (counter reset setelah 24 jam normal)
        ///   actions= restart/5000/restart/15000/restart/60000
        /// </summary>
        private void EnsureFailureActions(string serviceName)
        {
            try
            {
                string qfailureOutput = RunSc($"qfailure \"{serviceName}\"");

                // Kalau sudah ada "RESTART -- Delay" di output, sc failure sudah terkonfigurasi
                bool alreadyConfigured = qfailureOutput.Contains("RESTART", StringComparison.OrdinalIgnoreCase) &&
                                         qfailureOutput.Contains("Delay", StringComparison.OrdinalIgnoreCase);
                if (alreadyConfigured)
                {
                    SafeWriteEventLog("Application",
                        $"[RESILIENCE] sc failure sudah terkonfigurasi — tidak perlu perubahan.",
                        EventLogEntryType.Information, 1065);
                    return;
                }

                // Belum terkonfigurasi → set recovery actions
                SafeWriteEventLog("Application",
                    $"[RESILIENCE] sc failure belum terkonfigurasi — memperbaiki...",
                    EventLogEntryType.Warning, 1066);

                string failureOutput = RunSc(
                    $"failure \"{serviceName}\" reset= 86400 " +
                    $"actions= restart/5000/restart/15000/restart/60000");

                SafeWriteEventLog("Application",
                    $"[RESILIENCE] sc failure dikonfigurasi ulang. Output: '{failureOutput.Trim()}'",
                    EventLogEntryType.Information, 1067);
            }
            catch (Exception ex)
            {
                SafeWriteEventLog("Application",
                    $"[RESILIENCE] EnsureFailureActions error: {ex.Message}",
                    EventLogEntryType.Warning, 1068);
            }
        }

        /// <summary>
        /// Jalankan sc.exe dengan argumen tertentu, return stdout+stderr sebagai string.
        /// Timeout 10 detik — sc.exe lokal hampir selalu selesai dalam < 1 detik.
        /// </summary>
        private static string RunSc(string arguments)
        {
            using var process = new System.Diagnostics.Process
            {
                StartInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName               = "sc.exe",
                    Arguments              = arguments,
                    UseShellExecute        = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError  = true,
                    CreateNoWindow         = true
                }
            };

            process.Start();
            string output = process.StandardOutput.ReadToEnd() +
                            process.StandardError.ReadToEnd();
            process.WaitForExit(10_000); // timeout 10 detik
            return output;
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
                    // Interval 15 detik: worst-case gap kalau 6008/power loss = 15 detik,
                    // jauh lebih kecil dari sebelumnya (1 menit). Di environment dengan
                    // Security log 20MB yang cepat rotate dan riwayat 6008, gap kecil
                    // sangat penting agar replay window tidak kehilangan event login pagi.
                    // Overhead: nulis satu file kecil tiap 15 detik — tidak signifikan.
                    SaveStopCheckpoint(DateTime.UtcNow);
                }
                catch
                {
                    // Heartbeat must never crash service.
                }
            }, null, TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(15));
        }

        private static void SafeWriteEventLog(string source, string message, EventLogEntryType type, int eventId)
        {
            if (!_verboseLogging && _verboseOnlyEventIds.Contains(eventId))
                return;

            try
            {
                // Selalu pakai "Attendance-Service" — source yang terdaftar dengan message table.
                // Source "Application" adalah built-in Windows tanpa custom message table
                // sehingga Event Viewer menampilkan disclaimer panjang di setiap entry.
                EventLog.WriteEntry("Attendance-Service", message, type, eventId);
            }
            catch
            {
                // Ignore EventLog failures during shutdown windows.
            }
        }

        private void WriteAdminCorrelationLog(string message, EventLogEntryType type, int eventId)
            => SafeWriteEventLog("Application", message, type, eventId);

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
            // Self-healing: "already OK" confirmations — verbose only (tidak perlu tampil setiap boot normal)
            // Warning/fix IDs (1062, 1063, 1066, 1067) sengaja TIDAK di sini agar selalu tampil.
            1061, 1065,
            // Config validation: "OK" confirmation — verbose only.
            // Error/warning IDs (1070, 1071, 1072, 1073) sengaja TIDAK di sini agar selalu tampil.
            1075,
            // Health check: "OK" / info detail — verbose only.
            // Warning/error IDs (1079, 1081, 1084, 1085) sengaja TIDAK di sini — selalu tampil.
            // 1079 = subscription silent warning → selalu tampil (kondisi abnormal)
            // 1080 = re-subscribe OK → verbose (sukses, tidak perlu alert)
            // 1081 = re-subscribe attempt failed → selalu tampil (warning)
            // 1082 = mini-replay start → verbose
            // 1083 = mini-replay selesai → verbose
            // 1084 = mini-replay error → selalu tampil
            // 1085 = health check task error → selalu tampil
            1080, 1082, 1083,
            // Debug system event parsing — semua [DBG-*]
            2001, 2002, 2003, 2004, 2005, 2006, 2007, 2010, 2011, 2012, 2020, 2021,
            // Debug fallback resolution detail — [DBG-1074] resolved
            2013,
            // Debug RawEventStore fallback — [DBG-4624], [DBG-GetMRU], [DBG-42], [DBG-4634]
            2028, 2031, 2032, 2033,
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
                if (eventId != 4624 && eventId != 4647 && eventId != 4634)
                    continue;

                // Pre-filter 4624: skip irrelevant logon types saja.
                // Admin split-token filtering TIDAK dilakukan di sini — deferral ke
                // ProcessSecurityEntryAsync agar SaveRawSecurityEventAsync sempat
                // menyimpan metadata Logon ID yang dibutuhkan untuk korelasi 4634.
                if (eventId == 4624 && entry.Message != null)
                {
                    int lt = SecurityEventParser.ParseLogonType(entry.Message);
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

                // SaveRawSecurityEventAsync dipanggil di dalam ProcessSecurityEntryAsync
                // via writeRawRecord=true path — tidak perlu panggil lagi secara eksplisit.
                // Sebelumnya ada dua panggilan terpisah (eksplisit Task.Run + writeRawRecord),
                // yang menyebabkan double-write ke RawEventStore. RawEventStore.SaveAsync
                // memang idempotent via File.Exists, tapi race condition masih bisa terjadi
                // di window antara File.Exists check dan File.Move final.
                // Solusi: satu panggilan saja, lewat ProcessSecurityEntryAsync.
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

                // Admin session detection — gabungkan IsAdminLogon (field baru) dengan
                // IsAdminSplitTokenLogin dari MessageExcerpt (backward-compat file lama).
                bool isAdminRaw = raw.IsAdminLogon ||
                                  (eventId == 4624 && IsAdminSplitTokenLogin(raw.MessageExcerpt));

                if (eventId == 4624 && isAdminRaw)
                {
                    // Re-hydrate in-memory cache dari disk agar 4634 live yang datang
                    // setelah replay bisa dikorelasikan tanpa disk read lagi.
                    if (!string.IsNullOrEmpty(raw.LogonId))
                    {
                        _adminCorrelationService.RegisterAdminSession(
                            computerName,
                            raw.LogonId,
                            $"[ADMIN] Admin session re-hydrated from RawStore: " +
                            $"user={raw.Username} logonId={raw.LogonId} computer={computerName}");
                    }

                    // Gate: tidak di-enqueue, tidak di-dispatch, tidak ke SharePoint.
                    return;
                }

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
                    // 4634 tanpa username tidak bisa dipromosikan — skip saja.
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

                // 4634 dari RawEventStore: admin correlation gate + cek duplikat 4647.
                if (eventId == 4634)
                {
                    // ── Admin correlation gate (replay path) ─────────────────────────
                    // Logon ID disimpan di raw.LogonId (field baru) ATAU di MessageExcerpt.
                    string? logonId4634raw = !string.IsNullOrEmpty(raw.LogonId)
                        ? raw.LogonId
                        : SecurityEventParser.GetLogonId(raw.MessageExcerpt);

                    if (!string.IsNullOrEmpty(logonId4634raw))
                    {
                        if (_adminCorrelationService.IsAdminSession(computerName, logonId4634raw, eventTime, isReplay: true))
                        {
                            SafeWriteEventLog("Application",
                                $"[ADMIN] Skipping 4634 (raw replay) — paired 4624 is admin. " +
                                $"logonId={logonId4634raw} user={username} computer={computerName} time={eventTime:O}",
                                EventLogEntryType.Information, 2042);
                            return;
                        }
                    }
                    // ── End admin correlation gate ────────────────────────────────────

                    string workDate4634raw = eventTime.ToLocalTime().ToString("yyyy-MM-dd");
                    var allQueue4634raw = await eventQueue.GetAllAsync();

                    // Temporal dedup: sama dengan live path — skip 4634 yang fire
                    // dalam 30 detik setelah 4624 (stale session close saat unlock/CachedInteractive).
                    const int staleWindowSecondsRaw = 30;
                    bool isStaleRaw = allQueue4634raw.Any(x =>
                        x.EventId == 4624 &&
                        x.Username.Equals(username, StringComparison.OrdinalIgnoreCase) &&
                        x.ComputerName.Equals(computerName, StringComparison.OrdinalIgnoreCase) &&
                        x.EventTime.ToLocalTime().ToString("yyyy-MM-dd") == workDate4634raw &&
                        eventTime >= x.EventTime &&
                        (eventTime - x.EventTime).TotalSeconds <= staleWindowSecondsRaw);
                    if (isStaleRaw)
                    {
                        SafeWriteEventLog("Attendance-Service",
                            $"[DBG-4634] RawReplay skipped — stale session close within " +
                            $"{staleWindowSecondsRaw}s of 4624. " +
                            $"user='{username}' computer='{computerName}' time={eventTime:O}",
                            EventLogEntryType.Information, 2033);
                        return;
                    }

                    bool has4647raw = allQueue4634raw.Any(x =>
                        x.EventId == 4647 &&
                        x.Username.Equals(username, StringComparison.OrdinalIgnoreCase) &&
                        x.ComputerName.Equals(computerName, StringComparison.OrdinalIgnoreCase) &&
                        x.EventTime.ToLocalTime().ToString("yyyy-MM-dd") == workDate4634raw);
                    if (has4647raw)
                    {
                        SafeWriteEventLog("Attendance-Service",
                            $"[DBG-4634] RawReplay skipped — 4647 already queued for user='{username}' " +
                            $"computer='{computerName}' at {eventTime:O}",
                            EventLogEntryType.Information, 2033);
                        return;
                    }

                    await ProcessEvent(
                        4634, username, eventTime, computerName,
                        "Security", 0, null, writeRawRecord,
                        usernameResolutionSource: "Direct",
                        isFallback: true,
                        fallbackSource: "Event4634_Fallback4647",
                        status: "CONFIRMED");
                    return;
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
            dispatchBackoffSeconds = ReadIntListFromEnvironment(
                "DISPATCH_BACKOFF_SECONDS", new[] { 30, 60, 120, 300, 600 });

            ValidateConfiguration(config);

            return config;
        }

        /// <summary>
        /// Validasi semua field konfigurasi kritis saat startup.
        ///
        /// Tujuan: mendeteksi masalah konfigurasi SEBELUM service mencoba dispatch ke SharePoint
        /// (yang terjadi lazily saat event pertama masuk). Tanpa ini, credential yang salah
        /// atau field yang kosong baru ketahuan saat dispatch gagal dengan pesan error yang
        /// tidak jelas, bisa beberapa menit setelah service start.
        ///
        /// Level validasi:
        ///   CRITICAL  — field wajib ada dan tidak boleh kosong. Kalau kosong, service tidak bisa
        ///               kirim data ke SharePoint sama sekali. Log sebagai Error.
        ///   WARNING   — field opsional tapi penting. Kalau kosong, fitur tertentu tidak aktif.
        ///               Log sebagai Warning agar mudah dideteksi.
        ///   FORMAT    — field ada tapi format mencurigakan (misal TenantId bukan GUID).
        ///               Log sebagai Warning — tidak hard-fail karena format bisa valid meski tidak
        ///               sesuai ekspektasi.
        ///
        /// Tidak throw — validasi gagal tidak boleh mencegah service start sama sekali,
        /// karena RawEventStore + queue masih bisa menampung event meski SharePoint belum siap.
        /// </summary>
        private static void ValidateConfiguration(IConfiguration config)
        {
            bool hasError = false;

            // ── Helper lokal ──────────────────────────────────────────────────────
            void Critical(string key, string? value)
            {
                if (!string.IsNullOrWhiteSpace(value))
                    return;

                hasError = true;
                SafeWriteEventLog("Application",
                    $"[CONFIG] CRITICAL: '{key}' kosong atau tidak ditemukan di appsettings. " +
                    $"Service tidak bisa mengirim data ke SharePoint.",
                    EventLogEntryType.Error, 1070);
            }

            void Warn(string key, string? value, string reason)
            {
                if (!string.IsNullOrWhiteSpace(value))
                    return;

                SafeWriteEventLog("Application",
                    $"[CONFIG] WARNING: '{key}' kosong. {reason}",
                    EventLogEntryType.Warning, 1071);
            }

            void FormatWarn(string key, string? value, Func<string, bool> isValid, string hint)
            {
                if (string.IsNullOrWhiteSpace(value))
                    return; // sudah ter-cover oleh Critical/Warn

                if (!isValid(value))
                    SafeWriteEventLog("Application",
                        $"[CONFIG] WARNING: '{key}' = '{value}' format tidak sesuai ekspektasi. {hint}",
                        EventLogEntryType.Warning, 1072);
            }

            // ── AzureSettings ─────────────────────────────────────────────────────
            string? tenantId     = config["AzureSettings:TenantId"];
            string? clientId     = config["AzureSettings:ClientId"];
            string? clientSecret = config["AzureSettings:ClientSecret"];

            Critical("AzureSettings:TenantId",     tenantId);
            Critical("AzureSettings:ClientId",     clientId);
            Critical("AzureSettings:ClientSecret", clientSecret);

            // TenantId dan ClientId harus berupa GUID
            FormatWarn("AzureSettings:TenantId", tenantId,
                v => Guid.TryParse(v, out _),
                "Seharusnya berupa GUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx).");
            FormatWarn("AzureSettings:ClientId", clientId,
                v => Guid.TryParse(v, out _),
                "Seharusnya berupa GUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx).");

            // ClientSecret tidak boleh berisi placeholder literal
            if (!string.IsNullOrWhiteSpace(clientSecret))
            {
                string[] placeholders = { "YOUR_", "PLACEHOLDER", "CHANGE_ME", "TODO", "<", ">" };
                bool looksLikePlaceholder = Array.Exists(
                    placeholders, p => clientSecret.Contains(p, StringComparison.OrdinalIgnoreCase));
                if (looksLikePlaceholder)
                    SafeWriteEventLog("Application",
                        "[CONFIG] WARNING: 'AzureSettings:ClientSecret' sepertinya masih berisi " +
                        "placeholder dan belum diganti dengan nilai asli.",
                        EventLogEntryType.Warning, 1072);
            }

            // ── SharePointSettings ────────────────────────────────────────────────
            string? siteId      = config["SharePointSettings:SiteId"];
            string? listId      = config["SharePointSettings:ListId"];
            string? summaryListId = config["SharePointSettings:SummaryListId"];

            Critical("SharePointSettings:SiteId",  siteId);
            Critical("SharePointSettings:ListId",  listId);

            // SummaryListId opsional tapi kalau kosong fitur Summary nonaktif
            Warn("SharePointSettings:SummaryListId", summaryListId,
                "Fitur Summary (ClockIn/ClockOut harian) tidak akan aktif.");

            // ── AppSettings ───────────────────────────────────────────────────────
            // VerboseLogging tidak wajib — default false, tidak perlu divalidasi.

            // ── Hasil akhir ───────────────────────────────────────────────────────
            if (hasError)
            {
                SafeWriteEventLog("Application",
                    "[CONFIG] Satu atau lebih field CRITICAL kosong. " +
                    "Service tetap jalan tapi dispatch ke SharePoint akan gagal sampai config diperbaiki. " +
                    "Periksa Application EventLog event ID 1070 untuk detail.",
                    EventLogEntryType.Error, 1073);
            }
            else
            {
                SafeWriteEventLog("Application",
                    "[CONFIG] Validasi konfigurasi OK — semua field kritis terisi.",
                    EventLogEntryType.Information, 1075);
            }
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

        /// <summary>
        /// Called by SCM on power state changes (requires CanHandlePowerEvent = true in constructor).
        ///
        /// Tujuan utama: tangkap resume dari hibernate/suspend sebelum startup probe (90–120 detik)
        /// sempat mendeteksinya — memperkecil window buta dari ~90–120 detik menjadi ~2 detik.
        ///
        /// Saat PC resume dari hibernate, Windows dapat me-rotate Security dan/atau System log
        /// sebelum service sempat re-subscribe. Kedua subscription bisa drop tanpa notifikasi.
        /// Handler ini:
        ///   1. Reset ticks kedua subscription agar health check tahu ini adalah "fresh startup"
        ///      (bukan mid-day drop) dan startup probe aktif kembali.
        ///   2. Kick off re-subscribe + mini-replay untuk keduanya setelah delay 2 detik
        ///      (memberi Windows waktu commit log rotation sebelum kita re-attach).
        /// </summary>
        protected override bool OnPowerEvent(PowerBroadcastStatus powerStatus)
        {
            try
            {
                if (powerStatus == PowerBroadcastStatus.ResumeSuspend ||
                    powerStatus == PowerBroadcastStatus.ResumeAutomatic)
                {
                    SafeWriteEventLog("Application",
                        $"[POWER] Resume detected ({powerStatus}) — resetting subscription ticks " +
                        $"and scheduling re-subscribe + mini-replay for Security and System logs.",
                        EventLogEntryType.Information, 1086);

                    // Reset Security log counters — startup probe Security akan aktif kembali
                    Interlocked.Exchange(ref _subscriptionEnabledTicksUtc,   DateTime.UtcNow.Ticks);
                    Interlocked.Exchange(ref _lastSecurityEventTicksUtc,      DateTime.MinValue.Ticks);

                    // Reset System log counters — startup probe System akan aktif kembali
                    Interlocked.Exchange(ref _systemSubscriptionEnabledTicksUtc, DateTime.UtcNow.Ticks);
                    Interlocked.Exchange(ref _lastSystemEventTicksUtc,           DateTime.MinValue.Ticks);

                    var ct = cancellationToken ?? CancellationToken.None;

                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            // Delay 2 detik — beri Windows waktu untuk commit log rotation
                            // sebelum kita re-attach ke EventLog subscription.
                            await Task.Delay(2000, ct);

                            // Buffer 10 menit sebelum wake untuk tangkap event yang terjadi
                            // tepat saat resume sebelum service berhasil re-subscribe.
                            DateTime replayFrom = DateTime.UtcNow.AddMinutes(-10);
                            DateTime replayTo   = DateTime.UtcNow;

                            // Re-subscribe dan mini-replay Security log
                            await ResubscribeAndMiniReplayAsync(replayFrom, replayTo, 3, ct);

                            // Re-subscribe dan mini-replay System log
                            await ResubscribeSystemLogAndMiniReplayAsync(replayFrom, replayTo, 3, ct);
                        }
                        catch (OperationCanceledException) { /* service stopping */ }
                        catch (Exception ex)
                        {
                            SafeWriteEventLog("Application",
                                $"[POWER] Resume re-subscribe error: {ex.Message}",
                                EventLogEntryType.Warning, 1087);
                        }
                    }, ct);
                }
                else if (powerStatus == PowerBroadcastStatus.Suspend)
                {
                    // Simpan checkpoint sebelum suspend — kalau PC tidak resume normal
                    // (misal battery dead), replay berikutnya punya referensi yang benar.
                    SafeWriteEventLog("Application",
                        "[POWER] Suspend detected — saving stop checkpoint.",
                        EventLogEntryType.Information, 1086);

                    SaveStopCheckpoint(DateTime.UtcNow.AddSeconds(-5));
                }
            }
            catch (Exception ex)
            {
                SafeWriteEventLog("Application",
                    $"[POWER] OnPowerEvent error ({powerStatus}): {ex.Message}",
                    EventLogEntryType.Warning, 1087);
            }

            return true; // Must return true for ServiceBase to continue receiving power events
        }

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

                // FIX [HEALTH]: Monitor Security log subscription — bisa drop silent setelah log rotate.
                Task.Run(() => SecurityLogSubscriptionHealthCheckTask(cancellationToken), cancellationToken);

                // FIX [HEALTH-SYSTEM]: Monitor System log subscription — sumber event 42, 1074, 6006.
                // Shutdown detection path seluruhnya bergantung pada System log ini.
                Task.Run(() => SystemLogSubscriptionHealthCheckTask(cancellationToken), cancellationToken);

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

        /// <summary>
        /// Mendeteksi dan memulihkan Security log subscription yang drop secara silent.
        ///
        /// Dua skenario yang di-handle:
        ///   1. STARTUP DROP — subscription tidak pernah menerima event sejak di-enable.
        ///      Terjadi kalau Security log langsung di-rotate saat wake dari hibernate/fast-startup,
        ///      atau kalau log sudah penuh sebelum service start.
        ///      Deteksi: tidak ada Security event dalam probeStartupWindowSeconds setelah subscription di-enable.
        ///
        ///   2. MID-DAY DROP — subscription mati di tengah sesi setelah log rotate.
        ///      Terjadi karena Windows EventLog.EntryWritten subscription berhenti firing
        ///      tanpa exception atau notifikasi setelah Security log overwrite.
        ///      Deteksi: tidak ada Security event dalam threshold tertentu.
        ///      Threshold adaptif:
        ///        - Jam kerja (07:00–19:00): 30 menit — unlock/lock screen sangat sering
        ///        - Luar jam kerja: tidak enforce — bisa memang tidak ada activity
        ///
        /// Fast startup / hibernate awareness:
        ///   - Subscription bisa langsung drop saat wake kalau log sudah di-rotate sebelum hibernate
        ///   - Probe startup (90 detik) menangkap ini jauh lebih cepat dari threshold 30 menit
        ///
        /// Re-subscribe selalu diikuti mini-replay untuk menangkap event yang missed.
        /// </summary>
        private async Task SecurityLogSubscriptionHealthCheckTask(CancellationToken cancellationToken)
        {
            const int checkIntervalSeconds      = 30;   // cek setiap 30 detik (sebelumnya 5 menit)
            const int probeStartupWindowSeconds = 90;   // setelah startup, tunggu 90 detik untuk event pertama
            const int silentThresholdWorkHour   = 1800; // 30 menit di jam kerja
            const int maxResubscribeAttempts    = 3;
            const int workHourStart             = 7;
            const int workHourEnd               = 19;

            bool startupProbeCompleted = false;

            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(checkIntervalSeconds), cancellationToken);

                    long enabledTicks   = Interlocked.Read(ref _subscriptionEnabledTicksUtc);
                    long lastEventTicks = Interlocked.Read(ref _lastSecurityEventTicksUtc);
                    DateTime nowUtc     = DateTime.UtcNow;

                    double secondsSinceEnabled   = (nowUtc.Ticks - enabledTicks) / (double)TimeSpan.TicksPerSecond;
                    double secondsSinceLastEvent = lastEventTicks == DateTime.MinValue.Ticks
                        ? secondsSinceEnabled  // belum pernah ada event → hitung dari subscription enable
                        : (nowUtc.Ticks - lastEventTicks) / (double)TimeSpan.TicksPerSecond;

                    // ── PROBE STARTUP ──────────────────────────────────────────────────────
                    // Setelah subscription di-enable, tunggu probeStartupWindowSeconds.
                    // Kalau tidak ada Security event sama sekali dalam window itu → subscription
                    // kemungkinan besar drop (fast startup / hibernate / log sudah penuh saat wake).
                    // Tidak peduli jam kerja — startup bisa terjadi kapan saja.
                    if (!startupProbeCompleted && secondsSinceEnabled >= probeStartupWindowSeconds)
                    {
                        startupProbeCompleted = true;

                        if (lastEventTicks == DateTime.MinValue.Ticks)
                        {
                            // Tidak ada Security event sama sekali sejak subscription di-enable
                            SafeWriteEventLog("Application",
                                $"[HEALTH] Startup probe: no Security event in {probeStartupWindowSeconds}s since " +
                                $"subscription enabled. Possible hibernate resume or log rotation at wake. " +
                                $"Force re-subscribe + mini-replay.",
                                EventLogEntryType.Warning, 1079);

                            // Buffer 5 menit sebelum subscription untuk tangkap event yang terjadi
                            // tepat saat wake sebelum service berhasil subscribe.
                            DateTime missedSince = new DateTime(enabledTicks, DateTimeKind.Utc)
                                .Subtract(TimeSpan.FromMinutes(5));

                            await ResubscribeAndMiniReplayAsync(
                                missedSince, nowUtc, maxResubscribeAttempts, cancellationToken);
                        }
                        else
                        {
                            SafeWriteEventLog("Application",
                                $"[HEALTH] Startup probe OK: Security event received within " +
                                $"{secondsSinceEnabled:F0}s of subscription enable.",
                                EventLogEntryType.Information, 1080);
                        }

                        continue;
                    }

                    // ── MID-DAY DROP CHECK ─────────────────────────────────────────────────
                    // Setelah startup probe selesai, monitor terus untuk mid-day drop.
                    if (!startupProbeCompleted)
                        continue; // masih dalam window startup probe, belum saatnya cek mid-day

                    int hour        = DateTime.Now.Hour;
                    bool isWorkHour = hour >= workHourStart && hour < workHourEnd;

                    // Di luar jam kerja: skip mid-day check (wajar tidak ada Security event)
                    if (!isWorkHour)
                        continue;

                    if (secondsSinceLastEvent < silentThresholdWorkHour)
                        continue;

                    int silentMinutes = (int)(secondsSinceLastEvent / 60);
                    SafeWriteEventLog("Application",
                        $"[HEALTH] Mid-day drop detected: Security log silent {silentMinutes} min " +
                        $"(threshold={silentThresholdWorkHour / 60} min). Re-subscribe + mini-replay.",
                        EventLogEntryType.Warning, 1079);

                    DateTime midDayMissedSince = lastEventTicks == DateTime.MinValue.Ticks
                        ? new DateTime(enabledTicks, DateTimeKind.Utc)
                        : new DateTime(lastEventTicks, DateTimeKind.Utc);

                    await ResubscribeAndMiniReplayAsync(
                        midDayMissedSince, nowUtc, maxResubscribeAttempts, cancellationToken);
                }
                catch (TaskCanceledException) { break; }
                catch (Exception ex)
                {
                    SafeWriteEventLog("Application",
                        $"[HEALTH] SecurityLogSubscriptionHealthCheckTask error: {ex.Message}",
                        EventLogEntryType.Warning, 1085);

                    try { await Task.Delay(TimeSpan.FromMinutes(1), cancellationToken); }
                    catch (TaskCanceledException) { break; }
                }
            }
        }

        /// <summary>
        /// Re-subscribe Security log dan jalankan mini-replay untuk window yang missed.
        /// Dipanggil baik dari startup probe maupun mid-day drop detection.
        ///
        /// Setelah re-subscribe berhasil:
        ///   - _lastSecurityEventTicksUtc di-reset ke UtcNow agar mid-day cooldown
        ///     tidak langsung trigger lagi (threshold 30 menit dihitung ulang dari sini).
        ///   - _subscriptionEnabledTicksUtc di-reset ke UtcNow agar startup probe
        ///     tidak aktif lagi di iterasi berikutnya.
        /// </summary>
        private async Task ResubscribeAndMiniReplayAsync(
            DateTime missedSinceUtc,
            DateTime replayToUtc,
            int maxAttempts,
            CancellationToken cancellationToken)
        {
            bool resubscribed = false;

            for (int attempt = 1; attempt <= maxAttempts; attempt++)
            {
                try
                {
                    if (securityEventLog == null)
                    {
                        SafeWriteEventLog("Application",
                            "[HEALTH] securityEventLog is null — cannot re-subscribe.",
                            EventLogEntryType.Warning, 1081);
                        break;
                    }

                    securityEventLog.EnableRaisingEvents = false;
                    await Task.Delay(300, cancellationToken);
                    securityEventLog.EnableRaisingEvents = true;

                    // Reset kedua counter setelah re-subscribe berhasil:
                    //   _lastSecurityEventTicksUtc   → mid-day cooldown dihitung ulang dari sini
                    //   _subscriptionEnabledTicksUtc → probe startup tidak aktif di iterasi berikutnya
                    long nowTicks = DateTime.UtcNow.Ticks;
                    Interlocked.Exchange(ref _lastSecurityEventTicksUtc,   nowTicks);
                    Interlocked.Exchange(ref _subscriptionEnabledTicksUtc, nowTicks);

                    SafeWriteEventLog("Application",
                        $"[HEALTH] Re-subscribed OK (attempt {attempt}/{maxAttempts}).",
                        EventLogEntryType.Information, 1080);

                    resubscribed = true;
                    break;
                }
                catch (Exception ex)
                {
                    SafeWriteEventLog("Application",
                        $"[HEALTH] Re-subscribe attempt {attempt}/{maxAttempts} failed: {ex.Message}",
                        EventLogEntryType.Warning, 1081);

                    if (attempt < maxAttempts)
                        await Task.Delay(TimeSpan.FromSeconds(5), cancellationToken);
                }
            }

            if (!resubscribed)
                return;

            // Mini-replay: tangkap event yang missed selama subscription mati.
            // Security log sebagai sumber utama, RawEventStore sebagai fallback
            // kalau Security log sudah di-rotate sejak subscription drop.
            try
            {
                SafeWriteEventLog("Application",
                    $"[HEALTH] Mini-replay: from={missedSinceUtc:O} to={replayToUtc:O}",
                    EventLogEntryType.Information, 1082);

                // Jalankan di thread pool — ReplaySecurityEvents memanggil
                // ProcessSecurityEntryAsync secara sync (.GetAwaiter().GetResult())
                // sehingga perlu thread terpisah untuk hindari deadlock dari async context.
                await Task.Run(
                    () => ReplaySecurityEvents(missedSinceUtc, replayToUtc),
                    cancellationToken);

                await ReplayFromRawStore(missedSinceUtc, replayToUtc);

                SafeWriteEventLog("Application",
                    $"[HEALTH] Mini-replay done: from={missedSinceUtc:O} to={replayToUtc:O}",
                    EventLogEntryType.Information, 1083);
            }
            catch (Exception ex)
            {
                SafeWriteEventLog("Application",
                    $"[HEALTH] Mini-replay error: {ex.Message}",
                    EventLogEntryType.Warning, 1084);
            }
        }

        /// <summary>
        /// Mendeteksi dan memulihkan System log subscription yang drop secara silent.
        ///
        /// Berbeda dari SecurityLogSubscriptionHealthCheckTask:
        ///   - System log jarang menulis event di luar jam kerja → threshold berbasis
        ///     frekuensi ("30 menit tanpa event") tidak tepat. PC idle di luar jam kerja
        ///     memang tidak menghasilkan 1074/6006/42.
        ///   - Pendekatan: verifikasi eksplisit setiap N menit — query satu entry terbaru
        ///     dari System log secara manual (poll) dan bandingkan timestamp-nya dengan
        ///     waktu terakhir subscription kita menerima event. Kalau log ada entry baru
        ///     tapi subscription tidak pernah firing → drop terdeteksi.
        ///
        /// Dua skenario yang di-handle:
        ///   1. STARTUP DROP — tidak ada System event dalam probeStartupWindowSeconds,
        ///      tapi log secara manual punya entry baru (subscription drop, bukan idle).
        ///   2. POLL DROP — subscription mati di tengah sesi. Log punya entry lebih baru
        ///      dari _lastSystemEventTicksUtc dengan gap melebihi pollDropThresholdSeconds.
        ///
        /// Re-subscribe selalu diikuti mini-replay System log untuk event yang missed.
        /// </summary>
        private async Task SystemLogSubscriptionHealthCheckTask(CancellationToken cancellationToken)
        {
            // Cek setiap 5 menit — System log jarang menulis sehingga polling lebih jarang
            // dari Security (30 detik). Cukup responsif tanpa membebani EventLog API.
            const int checkIntervalSeconds      = 300;  // 5 menit
            const int probeStartupWindowSeconds = 120;  // 2 menit — lebih longgar dari Security (90s)
            const int pollDropThresholdSeconds  = 600;  // 10 menit gap log entry vs last kita terima
            const int maxResubscribeAttempts    = 3;
            const int workHourStart             = 7;
            const int workHourEnd               = 19;

            bool startupProbeCompleted = false;

            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(checkIntervalSeconds), cancellationToken);

                    if (systemEventLog == null)
                        continue;

                    long enabledTicks   = Interlocked.Read(ref _systemSubscriptionEnabledTicksUtc);
                    long lastEventTicks = Interlocked.Read(ref _lastSystemEventTicksUtc);
                    DateTime nowUtc     = DateTime.UtcNow;

                    double secondsSinceEnabled = (nowUtc.Ticks - enabledTicks) / (double)TimeSpan.TicksPerSecond;

                    // ── PROBE STARTUP ──────────────────────────────────────────────────────
                    // Tunggu probeStartupWindowSeconds setelah subscription di-enable.
                    // Kalau belum ada event, verifikasi eksplisit apakah log punya entry baru
                    // — membedakan "subscription drop" dari "log memang idle".
                    if (!startupProbeCompleted && secondsSinceEnabled >= probeStartupWindowSeconds)
                    {
                        startupProbeCompleted = true;

                        if (lastEventTicks == DateTime.MinValue.Ticks)
                        {
                            bool logHasRecentEntry = SystemLogHasRecentEntry(
                                new DateTime(enabledTicks, DateTimeKind.Utc).AddMinutes(-10),
                                nowUtc);

                            if (logHasRecentEntry)
                            {
                                SafeWriteEventLog("Application",
                                    $"[HEALTH-SYS] Startup probe: no System event in {probeStartupWindowSeconds}s " +
                                    $"but log has recent entries — subscription likely dropped. " +
                                    $"Force re-subscribe + mini-replay.",
                                    EventLogEntryType.Warning, 1088);

                                DateTime missedSince = new DateTime(enabledTicks, DateTimeKind.Utc)
                                    .Subtract(TimeSpan.FromMinutes(10));

                                await ResubscribeSystemLogAndMiniReplayAsync(
                                    missedSince, nowUtc, maxResubscribeAttempts, cancellationToken);
                            }
                            else
                            {
                                SafeWriteEventLog("Application",
                                    $"[HEALTH-SYS] Startup probe OK: no System event in {probeStartupWindowSeconds}s " +
                                    $"and log has no recent entries — likely idle/off-hours, subscription intact.",
                                    EventLogEntryType.Information, 1089);
                            }
                        }
                        else
                        {
                            SafeWriteEventLog("Application",
                                $"[HEALTH-SYS] Startup probe OK: System event received within " +
                                $"{secondsSinceEnabled:F0}s of subscription enable.",
                                EventLogEntryType.Information, 1089);
                        }

                        continue;
                    }

                    // ── POLL DROP CHECK ────────────────────────────────────────────────────
                    // Setelah startup probe selesai, polling berkala untuk mid-run drop.
                    // Hanya enforced saat jam kerja — di luar jam kerja System log memang idle.
                    if (!startupProbeCompleted)
                        continue;

                    int hour        = DateTime.Now.Hour;
                    bool isWorkHour = hour >= workHourStart && hour < workHourEnd;

                    if (!isWorkHour)
                        continue;

                    // Query entry terbaru dari System log secara manual.
                    // Kalau ada entry lebih baru dari _lastSystemEventTicksUtc dengan gap
                    // melebihi threshold → subscription tidak firing padahal ada event baru.
                    DateTime? latestLogEntry = GetLatestSystemLogEntryTime();
                    if (latestLogEntry == null)
                        continue;

                    long baselineTicks   = lastEventTicks == DateTime.MinValue.Ticks ? enabledTicks : lastEventTicks;
                    DateTime baselineUtc = new DateTime(baselineTicks, DateTimeKind.Utc);

                    double gapSeconds = (latestLogEntry.Value - baselineUtc).TotalSeconds;

                    if (gapSeconds > pollDropThresholdSeconds && latestLogEntry.Value > baselineUtc)
                    {
                        int gapMinutes = (int)(gapSeconds / 60);
                        SafeWriteEventLog("Application",
                            $"[HEALTH-SYS] Poll drop detected: System log latest entry={latestLogEntry.Value:O} " +
                            $"but last subscription event was {gapMinutes} min ago " +
                            $"(threshold={pollDropThresholdSeconds / 60} min). Re-subscribe + mini-replay.",
                            EventLogEntryType.Warning, 1088);

                        await ResubscribeSystemLogAndMiniReplayAsync(
                            baselineUtc, nowUtc, maxResubscribeAttempts, cancellationToken);
                    }
                }
                catch (TaskCanceledException) { break; }
                catch (Exception ex)
                {
                    SafeWriteEventLog("Application",
                        $"[HEALTH-SYS] SystemLogSubscriptionHealthCheckTask error: {ex.Message}",
                        EventLogEntryType.Warning, 1090);

                    try { await Task.Delay(TimeSpan.FromMinutes(1), cancellationToken); }
                    catch (TaskCanceledException) { break; }
                }
            }
        }

        /// <summary>
        /// Cek apakah System log punya setidaknya satu entry dalam rentang [fromUtc, toUtc].
        /// Dipakai oleh startup probe untuk membedakan "subscription drop" vs "log memang idle".
        /// Scan partial dari belakang (max 200 entry) — berhenti segera setelah menemukan satu match.
        /// </summary>
        private bool SystemLogHasRecentEntry(DateTime fromUtc, DateTime toUtc)
        {
            try
            {
                if (systemEventLog == null) return false;

                int count = systemEventLog.Entries.Count;
                for (int i = count - 1; i >= Math.Max(0, count - 200); i--)
                {
                    EventLogEntry entry = systemEventLog.Entries[i];
                    DateTime entryTime  = entry.TimeGenerated.ToUniversalTime();

                    if (entryTime < fromUtc)
                        break; // Entry sudah lebih lama dari fromUtc — tidak perlu scan lagi

                    if (entryTime <= toUtc)
                        return true;
                }
            }
            catch (Exception ex)
            {
                SafeWriteEventLog("Application",
                    $"[HEALTH-SYS] SystemLogHasRecentEntry error: {ex.Message}",
                    EventLogEntryType.Warning, 1090);
            }

            return false;
        }

        /// <summary>
        /// Ambil timestamp entry terbaru dari System log (entry index terakhir).
        /// Return null kalau log kosong atau tidak bisa dibaca.
        /// </summary>
        private DateTime? GetLatestSystemLogEntryTime()
        {
            try
            {
                if (systemEventLog == null) return null;

                int count = systemEventLog.Entries.Count;
                if (count == 0) return null;

                EventLogEntry latest = systemEventLog.Entries[count - 1];
                return latest.TimeGenerated.ToUniversalTime();
            }
            catch (Exception ex)
            {
                SafeWriteEventLog("Application",
                    $"[HEALTH-SYS] GetLatestSystemLogEntryTime error: {ex.Message}",
                    EventLogEntryType.Warning, 1090);
                return null;
            }
        }

        /// <summary>
        /// Re-subscribe System log dan jalankan mini-replay System events untuk window yang missed.
        /// Analog dengan ResubscribeAndMiniReplayAsync untuk Security log.
        ///
        /// Setelah re-subscribe berhasil:
        ///   - _lastSystemEventTicksUtc          → poll drop cooldown dihitung ulang dari UtcNow.
        ///   - _systemSubscriptionEnabledTicksUtc → startup probe tidak aktif di iterasi berikutnya.
        ///
        /// System replay diperpanjang 30 detik lebih awal agar 1074 yang terjadi tepat sebelum
        /// window tetap ter-load ke memory sebelum 6006 di-replay (sama seperti startup replay).
        /// </summary>
        private async Task ResubscribeSystemLogAndMiniReplayAsync(
            DateTime missedSinceUtc,
            DateTime replayToUtc,
            int maxAttempts,
            CancellationToken cancellationToken)
        {
            bool resubscribed = false;

            for (int attempt = 1; attempt <= maxAttempts; attempt++)
            {
                try
                {
                    if (systemEventLog == null)
                    {
                        SafeWriteEventLog("Application",
                            "[HEALTH-SYS] systemEventLog is null — cannot re-subscribe.",
                            EventLogEntryType.Warning, 1091);
                        break;
                    }

                    systemEventLog.EnableRaisingEvents = false;
                    await Task.Delay(300, cancellationToken);
                    systemEventLog.EnableRaisingEvents = true;

                    long nowTicks = DateTime.UtcNow.Ticks;
                    Interlocked.Exchange(ref _lastSystemEventTicksUtc,           nowTicks);
                    Interlocked.Exchange(ref _systemSubscriptionEnabledTicksUtc, nowTicks);

                    SafeWriteEventLog("Application",
                        $"[HEALTH-SYS] Re-subscribed System log OK (attempt {attempt}/{maxAttempts}).",
                        EventLogEntryType.Information, 1091);

                    resubscribed = true;
                    break;
                }
                catch (Exception ex)
                {
                    SafeWriteEventLog("Application",
                        $"[HEALTH-SYS] Re-subscribe System log attempt {attempt}/{maxAttempts} failed: {ex.Message}",
                        EventLogEntryType.Warning, 1091);

                    if (attempt < maxAttempts)
                        await Task.Delay(TimeSpan.FromSeconds(5), cancellationToken);
                }
            }

            if (!resubscribed)
                return;

            try
            {
                // Extend 30 detik lebih awal agar 1074 yang terjadi tepat di batas window
                // sudah ada di memory sebelum 6006 di-replay — konsisten dengan ReplayMissedEventsFromCheckpoint.
                DateTime extendedFrom = missedSinceUtc.AddSeconds(-30);

                SafeWriteEventLog("Application",
                    $"[HEALTH-SYS] Mini-replay System: from={extendedFrom:O} to={replayToUtc:O}",
                    EventLogEntryType.Information, 1092);

                // ReplaySystemEvents memanggil ProcessSystemEntryAsync secara sync (.GetAwaiter().GetResult())
                // → jalankan di thread pool untuk hindari deadlock dari async context.
                await Task.Run(
                    () => ReplaySystemEvents(extendedFrom, replayToUtc),
                    cancellationToken);

                SafeWriteEventLog("Application",
                    $"[HEALTH-SYS] Mini-replay System done: from={extendedFrom:O} to={replayToUtc:O}",
                    EventLogEntryType.Information, 1092);
            }
            catch (Exception ex)
            {
                SafeWriteEventLog("Application",
                    $"[HEALTH-SYS] Mini-replay System error: {ex.Message}",
                    EventLogEntryType.Warning, 1092);
            }
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
            // Login events (4624 normal): summary hanya first login of day.
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

            if (item.EventId == 1074 || item.EventId == 6006 || item.EventId == 4647)
                return true;

            // 4634: fallback logout — masuk summary hanya kalau tidak ada 4647 di group
            // yang sama (IsFallback4634 flag). Priority dikendalikan di
            // TryUpdateDailySummaryShutdownAsync via GetShutdownPriority.
            if (item.EventId == 4634)
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
        ///   4634 = 5 (fallback 4647 — Logoff event, unreliable tapi lebih baik dari system event)
        ///   1074 shutdown = 4 | 6006 confirmed = 3 | 42 = 0 (last resort)
        ///
        /// Perubahan dari versi sebelumnya:
        ///   - 4634 ditambahkan di priority 5 (di bawah 4647=6, di atas 1074=4).
        ///   - 1074 diturunkan dari 5 → 4 dan 6006 dari 4 → 3 untuk memberi ruang 4634.
        ///   - 42 tetap 0 (last resort).
        ///
        /// PENTING: Method ini harus di-sync dengan SharePointIntegration.GetShutdownPriority
        /// kalau method tersebut ada di sana.
        /// </summary>
        private static int GetShutdownEventPriority(int eventId, string eventType)
        {
            if (eventId == 4647) return 6; // Priority tertinggi — explicit user logoff dari Security log
            if (eventId == 4634) return 5; // Fallback 4647 — Logoff event, di bawah 4647 tapi di atas system events
            if (eventId == 1074 && !eventType.Contains("restart", StringComparison.OrdinalIgnoreCase)
                                && !eventType.Contains("reboot", StringComparison.OrdinalIgnoreCase)) return 4; // was 5
            if (eventId == 6006)
                return eventType.Contains("unconfirmed", StringComparison.OrdinalIgnoreCase) ? 0 : 3; // was 4
            if (eventId == 42)   return 0; // last resort — hanya kalau tidak ada event lain
            return 0;
        }

        private async Task<bool> TryDispatchQueuedEventAsync(QueuedAttendanceEvent item)
        {
            try
            {
                if (item.PendingUsernameResolution)
                {
                    bool resolved = await TryResolvePendingSystemUsernameAsync(item);
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
                            // 4634 (priority 5) juga lebih tinggi dari 6006 confirmed (3) —
                            // sama-sama dari Security log, biarkan dia dispatch.
                            if (item.EventId == 4647 || item.EventId == 4634)
                            {
                                // 4647/4634 menang — mark 6006 di group sebagai summaryDispatched
                                // agar 6006 tidak kirim summary lagi setelahnya.
                                await eventQueue.MarkGroupSummaryDispatchedAsync(item.ShutdownGroupId, exceptQueueId: item.QueueId);
                                SafeWriteEventLog("Application",
                                    $"[DISPATCH] Shutdown group: {item.EventId} takes priority over confirmed 6006. " +
                                    $"queueId={item.QueueId} groupId={item.ShutdownGroupId}",
                                    EventLogEntryType.Information, 4009);
                                // needsSummary tetap true — 4647/4634 yang dispatch
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
                    if (item.EventId == 4624)
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

        // ── Security log subscription health check ───────────────────────────────
        // Windows EventLog.EntryWritten subscription bisa drop secara silent setelah
        // Security log di-rotate (log penuh dan di-overwrite). Tidak ada exception,
        // tidak ada notifikasi — event handler berhenti firing tanpa jejak apapun.
        //
        // _lastSecurityEventTicksUtc: kapan terakhir OnSecurityEventWritten dipanggil.
        //   Init ke MinValue (bukan UtcNow) agar startup probe bisa membedakan
        //   "belum pernah ada event" vs "sudah ada event sebelumnya".
        //
        // _subscriptionEnabledTicksUtc: kapan EnableRaisingEvents = true terakhir dipanggil.
        //   Diset di OnStart() dan ResubscribeAndMiniReplayAsync() setiap kali
        //   subscription di-enable ulang.
        private long _lastSecurityEventTicksUtc   = DateTime.MinValue.Ticks;
        private long _subscriptionEnabledTicksUtc = DateTime.MinValue.Ticks;

        // ── System log subscription health check ────────────────────────────────
        // Sama seperti Security log health check, tapi untuk System log (sumber event
        // 42, 1074, 6006 — seluruh shutdown detection path bergantung padanya).
        //
        // Berbeda dari Security:
        //   - System log jarang menulis event di luar jam kerja → threshold berbasis
        //     frekuensi tidak cocok. Pakai verifikasi eksplisit (poll terbaru dari log).
        //   - _lastSystemEventTicksUtc dan _systemSubscriptionEnabledTicksUtc
        //     juga di-reset saat OnPowerEvent resume agar health check tahu ini
        //     fresh startup pasca-wake, bukan mid-day drop biasa.
        private long _lastSystemEventTicksUtc          = DateTime.MinValue.Ticks;
        private long _systemSubscriptionEnabledTicksUtc = DateTime.MinValue.Ticks;

        private void OnSecurityEventWritten(object sender, EntryWrittenEventArgs e)
        {
            if (e?.Entry == null) return;

            // Reset health check counter — subscription masih hidup
            Interlocked.Exchange(ref _lastSecurityEventTicksUtc, DateTime.UtcNow.Ticks);

            EventLogEntry entry = e.Entry;
            if (ShouldSkipLiveEntry(entry.TimeGenerated.ToUniversalTime(), isSecurityEvent: true))
                return;

            // Opsi 3: raw event dipersist di dalam ProcessSecurityEntryAsync (awal method,
            // sebelum semua gate) via writeRawRecord=true — tidak perlu panggil terpisah di sini.
            // Memindahkan save ke dalam ProcessSecurityEntryAsync menjamin:
            //   - tidak ada double-write (satu call path, satu save)
            //   - save dilakukan await sebelum admin cache dipopulate, menghilangkan race condition
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

        // FIX BUG-2: Grace period for Security log events (4624/4647) past replayUpperBound.
        // Rationale: 4647 (logout) and its paired 42 (sleep) fire within 2-3 seconds of each
        // other. The 4647 comes from Security log, 42 from System log. Without the grace period,
        // 4647 at the boundary is dropped while 42 passes → missing logout records.
        private static readonly TimeSpan LiveEventGracePeriod = TimeSpan.FromSeconds(10);

        private bool ShouldSkipLiveEntry(DateTime eventTime, bool isSecurityEvent = false)
        {
            // Security log events (4624/4647) get a grace period past replayUpperBound.
            DateTime effectiveBound = isSecurityEvent
                ? replayUpperBound.Add(LiveEventGracePeriod)
                : replayUpperBound;

            if (eventTime <= effectiveBound)
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
                if (eventId != 4624 && eventId != 4647 && eventId != 4634) return;

                DateTime eventTime = log.TimeGenerated.ToUniversalTime();
                string computerName = log.MachineName;
                string eventMessage = log.Message;

                // Persistensi ke RawEventStore dilakukan PERTAMA, sebelum semua gate.
                // Ini menjamin dua properti penting:
                //
                // 1. Anti double-write: satu-satunya tempat SaveRawSecurityEventAsync dipanggil
                //    untuk path ini. OnSecurityEventWritten tidak lagi memanggil secara terpisah,
                //    dan ReplaySecurityEvents juga tidak lagi memanggil eksplisit — keduanya
                //    bergantung pada panggilan di sini via writeRawRecord=true.
                //
                // 2. Race condition 4624→4634: save dilakukan secara await (bukan Task.Run fire-
                //    and-forget) agar admin LogonId sudah di disk DAN di in-memory cache sebelum
                //    proses berlanjut. Jika 4634 datang sangat cepat setelah 4624, RawStore
                //    lookup di gate 4634 sudah punya data yang dibutuhkan.
                //    SaveRawSecurityEventAsync juga populate admin correlation cache secara sinkron
                //    di dalam lock, sehingga cache read di gate 4634 (yang berjalan di thread
                //    lain) tidak bisa mendahului write.
                if (writeRawRecord)
                    await SaveRawSecurityEventAsync(log);

                // 4634 — Logoff (unreliable, used as fallback for 4647 when 4647 is absent).
                // Windows fires 4634 for every logoff including background/system sessions,
                // so it is inherently noisy. We only promote it as a logout event when
                // there is no 4647 already queued for the same user+computer+workDate
                // within a short dedup window. Priority: below 4647, above 1074/6006.
                // Username source: same "Subject:" section as 4647.
                if (eventId == 4634)
                {
                    // Re-use the 4647 username extraction path — same XML/message structure.
                    string? username4634 = SecurityEventParser.GetUsernameFromEvent(eventMessage, 4647);
                    if (string.IsNullOrEmpty(username4634) || !IsValidUsername(username4634))
                    {
                        SafeWriteEventLog("Application",
                            $"[DBG-4634] Username unresolvable at {eventTime:O} on {computerName} — skipped.",
                            EventLogEntryType.Information, 2033);
                        return;
                    }

                    string? sid4634 = SecurityEventParser.GetUserSidFromSecurityEvent(eventMessage, 4647);
                    username4634 = ResolveUsernameBySid(username4634, sid4634);
                    if (string.IsNullOrEmpty(username4634) || !IsValidUsername(username4634))
                        return;

                    // ── Admin session correlation gate ────────────────────────────────────
                    // Parse Logon ID dari section "Subject:" pada 4634 — ini adalah ID sesi
                    // yang ditutup, harus cocok dengan Logon ID dari paired 4624 admin.
                    // 4634 tidak membawa Elevated Token / Linked Logon ID, sehingga satu-satunya
                    // cara deteksi admin adalah via korelasi Logon ID ke 4624 yang sudah disimpan.
                    string? logonId4634 = SecurityEventParser.GetLogonId(eventMessage);

                    if (!string.IsNullOrEmpty(logonId4634))
                    {
                        if (_adminCorrelationService.IsAdminSession(computerName, logonId4634, eventTime, isReplay: false))
                        {
                            SafeWriteEventLog("Application",
                                $"[ADMIN] Skipping 4634 — paired 4624 session is admin. " +
                                $"logonId={logonId4634} user={username4634} computer={computerName} time={eventTime:O}",
                                EventLogEntryType.Information, 2042);
                            return; // tidak di-enqueue, tidak di-dispatch, tidak ke SharePoint
                        }
                    }
                    // ── End admin correlation gate ────────────────────────────────────────

                    // Check: apakah 4647 untuk user+computer+workDate ini sudah ada di queue?
                    // Kalau ada, 4634 tidak diperlukan — skip.
                    string workDate4634 = eventTime.ToLocalTime().ToString("yyyy-MM-dd");
                    var allQueue4634 = await eventQueue.GetAllAsync();

                    // Temporal dedup: skip 4634 yang fire dalam 30 detik setelah 4624 user yang sama.
                    // Ini adalah Windows behavior normal untuk logon type 11 (CachedInteractive /
                    // unlock screen) — Windows menutup sesi lama dan membuka sesi baru hampir
                    // bersamaan, menyebabkan 4634 (sesi lama ditutup) fire tepat setelah 4624 baru.
                    // 4634 seperti ini BUKAN logout user — jangan dispatch ke SharePoint.
                    // Window 30 detik aman: logout sesungguhnya selalu punya gap >> 30 detik dari login.
                    const int staleSessionWindowSeconds = 30;
                    bool isStaleSessionClose = allQueue4634.Any(x =>
                        x.EventId == 4624 &&
                        x.Username.Equals(username4634, StringComparison.OrdinalIgnoreCase) &&
                        x.ComputerName.Equals(computerName, StringComparison.OrdinalIgnoreCase) &&
                        x.EventTime.ToLocalTime().ToString("yyyy-MM-dd") == workDate4634 &&
                        eventTime >= x.EventTime &&
                        (eventTime - x.EventTime).TotalSeconds <= staleSessionWindowSeconds);
                    if (isStaleSessionClose)
                    {
                        SafeWriteEventLog("Attendance-Service",
                            $"[DBG-4634] Skipped — stale session close: 4634 fired within " +
                            $"{staleSessionWindowSeconds}s of 4624 login. " +
                            $"user='{username4634}' computer='{computerName}' time={eventTime:O}",
                            EventLogEntryType.Information, 2033);
                        return;
                    }

                    bool has4647 = allQueue4634.Any(x =>
                        x.EventId == 4647 &&
                        x.Username.Equals(username4634, StringComparison.OrdinalIgnoreCase) &&
                        x.ComputerName.Equals(computerName, StringComparison.OrdinalIgnoreCase) &&
                        x.EventTime.ToLocalTime().ToString("yyyy-MM-dd") == workDate4634);
                    if (has4647)
                    {
                        SafeWriteEventLog("Attendance-Service",
                            $"[DBG-4634] Skipped — 4647 already queued for user='{username4634}' " +
                            $"computer='{computerName}' at {eventTime:O}",
                            EventLogEntryType.Information, 2033);
                        return;
                    }

                    SafeWriteEventLog("Attendance-Service",
                        $"[DBG-4634] Promoting as fallback logout: user='{username4634}' " +
                        $"computer='{computerName}' at {eventTime:O} (no 4647 found in queue)",
                        EventLogEntryType.Information, 2033);

                    await ProcessEvent(
                        4634, username4634, eventTime, computerName,
                        "Security", 0, null, writeRawRecord,
                        usernameResolutionSource: "Direct",
                        isFallback: true,
                        fallbackSource: "Event4634_Fallback4647",
                        status: "CONFIRMED");
                    return;
                }

                // Parse logon type (only relevant for 4624)
                int logonType = 0;
                if (eventId == 4624)
                    logonType = SecurityEventParser.ParseLogonType(eventMessage);

                if (eventId == 4624 && !IsRelevantLogonType(logonType))
                    return;

                // Deteksi admin (UAC split token) login.
                // Windows membuat 2 event 4624 untuk admin login:
                //   - Elevated Token: Yes  (high integrity token)
                //   - Elevated Token: No   (filtered standard token)
                // Keduanya punya Linked Logon ID non-zero yang saling pointing.
                bool isAdminLogin = eventId == 4624 && IsAdminSplitTokenLogin(eventMessage);

                if (isAdminLogin)
                {
                    // Ekstrak Logon ID dari section "New Logon:" — ini adalah ID sesi yang dibuka.
                    string? adminExcerpt = eventMessage != null
                        ? SecurityEventParser.ExtractMessageSection(eventMessage, 4624, 600)
                        : null;
                    string? adminLogonId = SecurityEventParser.GetLogonId(adminExcerpt ?? eventMessage);

                    // Populate in-memory correlation cache agar 4634 yang tiba nanti
                    // bisa di-korelasikan tanpa disk read.
                    if (!string.IsNullOrEmpty(adminLogonId))
                    {
                        _adminCorrelationService.RegisterAdminSession(
                            computerName,
                            adminLogonId,
                            $"[ADMIN] Admin session cached for correlation (live 4624): " +
                            $"logonId={adminLogonId} computer={computerName}");
                    }

                    // Gate: jangan enqueue atau dispatch — admin session tidak boleh sampai ke SharePoint.
                    return;
                }

                string? username = SecurityEventParser.GetUsernameFromEvent(eventMessage, eventId);
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

                string? sid = SecurityEventParser.GetUserSidFromSecurityEvent(eventMessage, eventId);
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

            // Reset System log health check counter — subscription masih hidup.
            // Dipakai oleh SystemLogSubscriptionHealthCheckTask untuk mendeteksi
            // subscription drop pasca log-rotate atau resume dari hibernate.
            Interlocked.Exchange(ref _lastSystemEventTicksUtc, DateTime.UtcNow.Ticks);

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

                // 6008 and 41 — Application Log warning only, not enqueued to SharePoint.
                if (eventId == 6008 || eventId == 41)
                {
                    string label = eventId == 6008 ? "Unexpected Shutdown" : "System Crash";
                    SafeWriteEventLog("Application",
                        $"[SYSTEM] Event {eventId} ({label}) detected at {eventTime:O} on {computerName} — logged as warning, not dispatched.",
                        EventLogEntryType.Warning, eventId == 6008 ? 6008 : 41);
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
                        // 4634: Logoff (fallback untuk 4647) — tidak reliable, dipakai hanya
                        // saat 4647 tidak tersedia. Label dibedakan agar mudah diidentifikasi
                        // di SharePoint sebagai fallback event, bukan primary logout.
                        4634 => "User Logoff (Fallback 4634)",
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
                        42   => "Sleep",
                        _    => "Unknown System Event"
                    },
                    _ => "Unknown Event"
                };

                if (eventTime.Kind == DateTimeKind.Unspecified)
                    eventTime = DateTime.SpecifyKind(eventTime, DateTimeKind.Local);

                if (eventId == 1074 || eventId == 6006 || eventId == 4647 || eventId == 4634 || eventId == 42)
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
                else if (eventId == 1074 || eventId == 6006 || eventId == 4647)
                {
                    shutdownTime = eventTime;
                    shutdownType = $"{eventId} - {eventType}";
                }
                // 4634: fallback logout — set shutdownTime seperti 4647.
                // Priority lebih rendah dari 4647; TryUpdateDailySummaryShutdownAsync
                // akan menolak update kalau 4647 sudah ada (GetShutdownPriority: 4634 < 4647).
                else if (eventId == 4634)
                {
                    shutdownTime = eventTime;
                    shutdownType = $"4634 - {eventType}";
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
                ParsedSecurityEvent parsed = SecurityEventParser.Parse(entry);
                int eventId = parsed.EventId;
                if (eventId != 4624 && eventId != 4647 && eventId != 4634)
                    return;

                string? message = parsed.Message;
                string? excerpt = parsed.MessageExcerpt;

                // Deteksi admin split-token SEBELUM memutuskan apa yang disimpan —
                // tapi JANGAN return di sini. Metadata sesi harus dipersist agar
                // korelasi 4634 tetap bekerja setelah service restart.
                bool isAdmin = eventId == 4624 && IsAdminSplitTokenLogin(message ?? excerpt);

                // Parse Logon ID dari section "New Logon:" untuk 4624,
                // sehingga kita mendapat ID dari sesi yang dibuka (bukan Subject/caller).
                string? logonId = parsed.LogonId;
                string? username = parsed.Username;
                string? sid = parsed.Sid;
                int logonType = parsed.LogonType;

                var raw = new RawSecurityEvent
                {
                    EventId        = eventId,
                    ComputerName   = entry.MachineName,
                    EventTimeUtc   = entry.TimeGenerated.ToUniversalTime(),
                    LogonType      = logonType,
                    Username       = username,
                    Sid            = sid,
                    MessageExcerpt = excerpt,
                    Source         = "Security",
                    // Field baru — membawa identitas admin session ke disk
                    LogonId        = logonId,
                    IsAdminLogon   = isAdmin
                };

                // SELALU simpan — termasuk admin session.
                // RawEventStore kini berfungsi ganda: replay storage DAN session-correlation cache.
                // Menyimpan admin event ke disk TIDAK berarti di-enqueue atau di-dispatch.
                await rawEventStore.SaveAsync(raw);

                // Populate in-memory admin cache agar 4634 yang tiba di proses yang sama
                // bisa dikorelasikan tanpa disk read. Disk copy menangani skenario cross-restart.
                if (isAdmin && !string.IsNullOrEmpty(logonId))
                {
                    _adminCorrelationService.RegisterAdminSession(
                        entry.MachineName,
                        logonId,
                        $"[ADMIN] Admin session saved for correlation: " +
                        $"user={username} logonId={logonId} computer={entry.MachineName}");
                }
            }
            catch { /* jangan crash service */ }
        }

        /// <summary>
        /// Ambil raw security events dari RawEventStore untuk workDate tertentu.
        /// Dipanggil sebagai fallback di ResolveFirst4624ForWorkDateAsync
        /// kalau Security log lokal kosong atau ter-rotate.
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
                            int lt = SecurityEventParser.ParseLogonType(entry.Message);
                            if (!IsRelevantLogonType(lt))
                                continue;
                        }

                        string? u = SecurityEventParser.GetUsernameFromEvent(entry.Message, secEventId);
                        if (!string.IsNullOrEmpty(u) && IsValidUsername(u))
                            return u;
                    }
                }
            }
            catch { /* silent fail */ }

            return null;
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

                    int lt = SecurityEventParser.ParseLogonType(entry.Message);
                    if (requireRelevant4624 && !IsRelevantLogonType(lt))
                        continue;

                    string? u = SecurityEventParser.GetUsernameFromEvent(entry.Message, secEventId);
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

        /// <summary>
        /// Tentukan apakah event 42 (Sleep/Modern Standby) boleh dipakai sebagai ShutdownTime.
        ///
        /// Dua skenario yang ditangani:
        ///
        ///   A. Fast Startup + Sleep tanpa 4647:
        ///      Saat Fast Startup diaktifkan, Windows kadang tidak menulis 4647 dan 1074/6006
        ///      saat user klik Sleep. Satu-satunya marker yang tersisa adalah event 42.
        ///      Dalam skenario ini 42 harus dipromosikan sebagai shutdown event.
        ///
        ///   B. Last-resort generik:
        ///      Tidak ada event shutdown lebih baik (4647, 4634, 1074, 6006-confirmed) sama sekali,
        ///      dan tidak ada wake event setelah 42 ini.
        ///
        /// Rules (semua harus terpenuhi):
        ///   1. Tidak ada event shutdown "lebih baik" di queue untuk user+computer+workDate ini
        ///      (4647, 4634, 1074, 6006-confirmed). Kalau ada, biarkan mereka yang update summary.
        ///   2. Tidak ada wake event (4624) setelah 42 ini di workDate yang sama.
        ///      Kalau ada wake setelah 42 → 42 bukan sleep final → skip.
        ///   3. Username sudah resolved (bukan __UNRESOLVED__).
        ///   4. Minimal 15 detik setelah event time agar event lain sempat masuk queue.
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

            // Syarat 1: cek apakah ada event shutdown lebih baik di queue.
            // 4634 (fallback 4647) juga dianggap "lebih baik" dari 42 — kalau 4634 sudah ada,
            // 42 tidak perlu dipromosikan sebagai last-resort.
            var allItems = await eventQueue.GetAllAsync();
            bool hasBetterShutdown = allItems.Any(x =>
                x.QueueId != item.QueueId &&
                x.Username.Equals(item.Username, StringComparison.OrdinalIgnoreCase) &&
                x.ComputerName.Equals(item.ComputerName, StringComparison.OrdinalIgnoreCase) &&
                x.EventTime.ToLocalTime().ToString("yyyy-MM-dd") == workDate &&
                (x.EventId == 1074 || x.EventId == 4647 || x.EventId == 4634 ||
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
                $"[DBG-42] Promoting as shutdown (no better event, no wake after). " +
                $"Likely Sleep-as-shutdown scenario (Fast Startup / user clicked Sleep without 4647/1074). " +
                $"computer={item.ComputerName} user={item.Username} sleepTime={item.EventTime:O}",
                EventLogEntryType.Information, 2032);
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
                        int lt = SecurityEventParser.ParseLogonType(message);
                        if (!IsRelevantLogonType(lt) || IsAdminSplitTokenLogin(message))
                            continue;

                        string? username = SecurityEventParser.GetUsernameFromEvent(message, 4624);
                        if (string.IsNullOrWhiteSpace(username))
                            continue;

                        string? sid = SecurityEventParser.GetUserSidFromSecurityEvent(message, 4624);
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
                    $"[DBG-StartupAnchor] Failed to scan startup anchor for {computerName} at {eventTime:O}: {ex.Message}",
                    EventLogEntryType.Warning, 2029);
                return false;
            }
        }

        private static bool IsStartupAnchorEventId(int eventId)
            => eventId == 12 || eventId == 6009;

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

                // Prune entries lebih dari 2 hari — dictionary ini tidak pernah di-clear
                // sehingga bisa tumbuh tanpa batas pada service yang jalan berbulan-bulan.
                // Key format: "COMPUTER::yyyy-MM-dd" — parse date dari suffix.
                // Lakukan prune berkala hanya kalau dictionary sudah cukup besar (>50 entries)
                // agar tidak ada overhead per-event saat jumlah entry masih kecil.
                if (firstLogon4624ByDeviceWorkDate.Count > 50)
                {
                    string cutoffDate = DateTime.Today.AddDays(-2).ToString("yyyy-MM-dd");
                    var toRemove = new List<string>();
                    foreach (var k in firstLogon4624ByDeviceWorkDate.Keys)
                    {
                        // Key format: "{computerName}::{yyyy-MM-dd}"
                        int sep = k.LastIndexOf("::", StringComparison.Ordinal);
                        if (sep >= 0 && string.Compare(k.Substring(sep + 2), cutoffDate, StringComparison.Ordinal) < 0)
                            toRemove.Add(k);
                    }
                    foreach (var k in toRemove)
                    {
                        firstLogon4624ByDeviceWorkDate.Remove(k);
                        allLogon4624ByDeviceWorkDate.Remove(k);
                        startupAnchorByDeviceWorkDate.Remove(k);
                    }
                }
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

        private string ResolveUsernameBySid(string username, string? sid)
        {
            string fallback = SecurityEventParser.NormalizeDisplayUsername(username);
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
                string translated = SecurityEventParser.NormalizeDisplayUsername(ntAccount?.Value ?? string.Empty);

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

                    candidate = SecurityEventParser.NormalizeDisplayUsername(candidate);

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
                        // FIX: NormalizeDisplayUsername wajib dipanggil di sini seperti Pattern 1 & 2.
                        // Tanpa ini, UPN prefix (nyoman.maheswari) dari Pattern 3 tidak di-TitleCase
                        // sehingga username tidak konsisten dengan output 4647 dan 1074 Pattern 1.
                        string candidate = SecurityEventParser.NormalizeDisplayUsername(domainMatch.Groups[1].Value.Trim());
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

                // ── FIX BUG-3: Forward search: 1074 that arrives AFTER this 6006 ────────
                // Windows occasionally logs 6006 before 1074 completes writing (inverted order).
                // Search for a 1074 within 180 seconds AFTER this 6006.
                // Only used when no backward candidate was found at all.
                // Safety: if a restart 1074 is found in the forward window, do NOT pair it.
                const double forwardWindowSeconds = 180.0;
                Last1074State? forwardCandidate = null;
                double forwardDiffSeconds = double.MaxValue;

                for (int i = 0; i < last1074States.Count; i++)
                {
                    Last1074State candidate = last1074States[i];
                    if (candidate.EventTime <= eventTime)
                        continue; // already handled by backward search

                    double diffSeconds = (candidate.EventTime - eventTime).TotalSeconds;
                    if (diffSeconds > forwardWindowSeconds)
                        continue;

                    if (IsRestartShutdownType(candidate.ShutdownType))
                        continue; // never pair a restart 1074

                    if (forwardCandidate == null || diffSeconds < forwardDiffSeconds)
                    {
                        forwardCandidate   = candidate;
                        forwardDiffSeconds = diffSeconds;
                    }
                }

                if (forwardCandidate != null)
                {
                    SafeWriteEventLog("Application",
                        $"[DBG-6006] TryResolve: FORWARD match (inverted order) username='{forwardCandidate.Username}' " +
                        $"diff=+{forwardDiffSeconds:F1}s 1074Type='{forwardCandidate.ShutdownType}' 6006Time={eventTime:O}",
                        EventLogEntryType.Information, 2012);
                    return (forwardCandidate.Username, forwardCandidate.ShutdownType);
                }

                if (fallbackCandidate == null)
                {
                    SafeWriteEventLog("Application",
                        $"[DBG-6006] TryResolve: no 1074 candidate in <=120s window before 6006 " +
                        $"and no forward match. 6006Time={eventTime:O}",
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
            return eventId == 1074 || eventId == 6006 || eventId == 4647 || eventId == 4634 || eventId == 42;
        }

        private static string BuildPendingFallbackSource(int eventId)
            => $"Event{eventId}_Pending";

        // #3: IsValidUsername static agar tidak ada implicit instance capture.
        private static bool IsValidUsername(string username)
        {
            return SecurityEventParser.IsValidUsername(username);
        }
    }
}