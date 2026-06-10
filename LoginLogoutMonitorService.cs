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
using System.Reflection;

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
        private readonly object knownLoginLock = new object();
        private readonly object firstLogonLock = new object();
        private readonly object startupAnchorLock = new object();
        private int activeDispatchCount = 0;
        private DateTime serviceStartTime;
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
        private DateTime _lastDictPruneDate = DateTime.MinValue.Date;

        // Semua 4624 per computer per hari — dipakai untuk isNewSession check di shutdown dispatch.
        // Berbeda dari firstLogon4624ByDeviceWorkDate yang hanya simpan earliest login,
        // dictionary ini simpan semua login agar bisa detect sesi baru setelah shutdown pertama.
        private readonly Dictionary<string, List<DateTime>> allLogon4624ByDeviceWorkDate =
            new Dictionary<string, List<DateTime>>(StringComparer.OrdinalIgnoreCase);
        private readonly object _allLogon4624Lock = new object();
        private readonly Dictionary<string, DateTime> startupAnchorByDeviceWorkDate =
            new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);

        // ── Admin session correlation service ────────────────────────────────────
        private readonly AdminSessionCorrelationService _adminCorrelationService;
        private readonly CheckpointService _checkpointService;
        private readonly ReplayService _replayService;

        // ── Deferred 4634 retry queue — startup warmup protection ────────────────
        //
        // Masalah: live 4634 bisa tiba sebelum replay/correlation selesai hydrate.
        // Akibatnya admin gate memberi hasil salah (false-pass atau false-block)
        // karena _adminSessions belum terisi dari RawStore.
        //
        // Solusi: event 4634 yang datang sebelum warmup selesai TIDAK diproses langsung
        // dan TIDAK di-drop — di-hold di queue ini, lalu di-reprocess ulang (full
        // re-evaluation) setelah warmup selesai.
        //
        // Properti:
        //   - ConcurrentQueue: lock-free enqueue dari OnSecurityEventWritten thread-pool thread.
        //   - Setiap entry menyimpan EventLogEntry + waktu pertama tiba + retry count.
        //   - Bounded: max Deferred4634MaxCapacity entry (safety valve).
        //   - Reprocessing via ProcessSecurityEntryAsync biasa (writeRawRecord=false).
        private readonly System.Collections.Concurrent.ConcurrentQueue<Deferred4634Entry> _deferred4634Queue
            = new System.Collections.Concurrent.ConcurrentQueue<Deferred4634Entry>();

        // Atomic counter — dipakai untuk capacity check tanpa full queue enumeration.
        private int _deferred4634Count = 0;
        private const int Deferred4634MaxCapacity = 200;

        // Max umur entry di deferred queue sebelum fallback ke processing normal.
        // 30 detik: cukup panjang untuk startup warmup selesai di hardware lambat sekalipun,
        // tapi tidak terlalu lama sehingga logout tidak tercatat sama sekali.
        private static readonly TimeSpan Deferred4634MaxAge = TimeSpan.FromSeconds(30);

        // Max retry attempts per entry sebelum fallback.
        private const int Deferred4634MaxRetry = 3;

        // ── Startup warmup state ──────────────────────────────────────────────────
        //
        // Dua kondisi KEDUANYA harus true sebelum live 4634 boleh diproses langsung:
        //
        //   _replayService.IsReplayInProgress == false  →  replay selesai
        //   _adminCacheWarm == true                     →  grace delay sudah lewat
        //
        // Mengapa perlu _adminCacheWarm di samping IsReplayInProgress?
        // ReplayMissedEventsFromCheckpoint() menandai replayInProgress=false SEBELUM
        // ProcessRawSecurityEventAsync (yang meng-hydrate _adminSessions) selesai commit —
        // ada jeda kecil di mana replay "selesai" tapi cache belum penuh.
        // _adminCacheWarm = true hanya di-set setelah grace delay lewat di DrainDeferred4634Async.
        //
        // volatile: dibaca dari OnSecurityEventWritten thread-pool tanpa lock.
        private volatile bool _adminCacheWarm = false;

        // ── Background task supervision ─────────────────────────────────────────
        private Task? cleanupTask;
        private Task? queueTask;
        private Task? securityHealthTask;
        private Task? systemHealthTask;
        private Task? heartbeatTask;
        private Task? supervisorTask;
        private Task? watchdogTask;
        private Timer? _supervisorWatchdogTimer;

        private CancellationTokenSource? _cleanupTaskCts;
        private CancellationTokenSource? _queueTaskCts;
        private CancellationTokenSource? _securityHealthTaskCts;
        private CancellationTokenSource? _systemHealthTaskCts;
        private CancellationTokenSource? _heartbeatTaskCts;

        private readonly object _backgroundTaskLock = new object();
        private readonly Queue<DateTime> _cleanupRestartHistory = new Queue<DateTime>();
        private readonly Queue<DateTime> _queueRestartHistory = new Queue<DateTime>();
        private readonly Queue<DateTime> _securityHealthRestartHistory = new Queue<DateTime>();
        private readonly Queue<DateTime> _systemHealthRestartHistory = new Queue<DateTime>();
        private readonly Queue<DateTime> _heartbeatRestartHistory = new Queue<DateTime>();
        private const int RestartFailureThreshold = 5;
        private static readonly TimeSpan RestartFailureWindow = TimeSpan.FromMinutes(30);

        private int queueAlertThreshold = 500;
        private bool queueThresholdAlerted = false;
        private int[] dispatchBackoffSeconds = new[] { 30, 60, 120, 300, 600 };
        private string? _heartbeatListId;
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

        private readonly PersistentEventQueue eventQueue =
            new PersistentEventQueue(Path.Combine(DataDirectory, "queue"));

        private readonly SummaryCache summaryCache;

        private readonly PersistentLogonIndex allLogon4624IndexStore =
            new PersistentLogonIndex(Path.Combine(DataDirectory, "all-logon-4624-index.json"));

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
        /// Mewakili satu event 4634 yang di-defer dari live pipeline karena warmup belum selesai.
        /// Menyimpan entry asli, timestamp pertama tiba, dan retry counter.
        /// Immutable setelah konstruksi — RetryCount diincrement via WithRetry().
        /// </summary>
        private sealed class Deferred4634Entry
        {
            public EventLogEntry Entry        { get; }
            public DateTime      ArrivedUtc   { get; }
            public int           RetryCount   { get; }

            public Deferred4634Entry(EventLogEntry entry, DateTime arrivedUtc, int retryCount = 0)
            {
                Entry      = entry;
                ArrivedUtc = arrivedUtc;
                RetryCount = retryCount;
            }

            /// <summary>Buat instance baru dengan RetryCount+1 untuk re-enqueue setelah gagal.</summary>
            public Deferred4634Entry WithRetry()
                => new Deferred4634Entry(Entry, ArrivedUtc, RetryCount + 1);

            /// <summary>True jika entry sudah melewati batas usia maksimum.</summary>
            public bool IsExpired(TimeSpan maxAge)
                => (DateTime.UtcNow - ArrivedUtc) > maxAge;

            /// <summary>True jika sudah mencapai batas maksimum retry.</summary>
            public bool IsRetryExhausted(int maxRetry)
                => RetryCount >= maxRetry;
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
            _adminCorrelationService.InitBootSessionId(DataDirectory);
            _checkpointService = new CheckpointService(DataDirectory, MaxReplayLookback, SafeWriteEventLog);
            summaryCache = new SummaryCache(
                Path.Combine(DataDirectory, "summary-cache.json"),
                (msg, type, id) => SafeWriteEventLog("Attendance-Service", msg, type, id));

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

            _checkpointService.EnsureCheckpointBootstrap();

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

            _replayService = new ReplayService(
                _checkpointService,
                eventQueue,
                rawEventStore,
                securityEventLog,
                systemEventLog,
                SafeWriteEventLog,
                GetNormalizedEventId,
                IsRelevantLogonType,
                ProcessSecurityEntryAsync,
                ProcessSystemEntryAsync,
                ProcessRawSecurityEventAsync);
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
            long subscriptionEnabledTicks = DateTime.UtcNow.Ticks;
            Interlocked.Exchange(ref _subscriptionEnabledTicksUtc, subscriptionEnabledTicks);
            Interlocked.Exchange(ref _systemSubscriptionEnabledTicksUtc, subscriptionEnabledTicks);
            Interlocked.Exchange(ref _securityProbeEpochTicks, subscriptionEnabledTicks);

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

                    _checkpointService.EnsureCheckpointBootstrap();

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

                            // MUST be first — configure sc failure actions before any other startup work
                            // so that even if startup crashes, the service will be restarted by SCM.
                            // Self-healing: pastikan startup type tetap Automatic dan
                            // sc failure recovery action tetap terkonfigurasi.
                            // Dijalankan setiap service start agar Windows Update atau
                            // Group Policy yang me-reset konfigurasi ini langsung diperbaiki.
                            EnsureServiceResilience();

                            LoadPersistedAllLogon4624IndexAsync(ct).GetAwaiter().GetResult();
                            PrimeFirstLogonIndexFromQueueAsync(ct).GetAwaiter().GetResult();

                            // EnableRaisingEvents sudah diaktifkan di OnStart() sebelum delay
                            // dan sebelum background thread ini jalan — tidak perlu set lagi di sini.

                            // FIX [ADMIN-GATE]: Replay DULU sebelum RetryPendingQueue.
                            // ReplayMissedEventsFromCheckpoint() meng-hydrate _adminSessions dari
                            // RawEventStore melalui ProcessRawSecurityEventAsync (4624 admin →
                            // RegisterAdminSession). Jika RetryPendingQueueOnStartupAsync berjalan
                            // lebih dulu, event 4624 admin yang tersimpan di persistent queue
                            // (karena network failure di sesi sebelumnya) akan langsung di-dispatch
                            // ke SharePoint melalui TryDispatchQueuedEventAsync — yang tidak punya
                            // admin gate — sehingga admin lolos ke rawListId dan summaryListId.
                            _replayService.ReplayMissedEventsFromCheckpoint().GetAwaiter().GetResult();

                            // Persistent queue di-dispatch setelah admin cache ter-hydrate.
                            RetryPendingQueueOnStartupAsync(ct).GetAwaiter().GetResult();

                            // Drain deferred 4634 events yang di-defer selama startup warmup.
                            // Fire-and-forget: tidak block checkpoint heartbeat atau live monitoring.
                            // DrainDeferred4634Async() set _adminCacheWarm=true setelah grace delay,
                            // sehingga live 4634 berikutnya tidak masuk deferred queue lagi.
                            _ = Task.Run(() => DrainDeferred4634Async(cancellationToken.Value));

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
                                $"[STARTUP] Background startup thread failed: {ex}",
                                EventLogEntryType.Error, 1002);
                            try { _checkpointService.SaveStopCheckpoint(DateTime.UtcNow.AddSeconds(-5)); } catch { }
                            try { Stop(); } catch { }
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
                            $"EmployeeLoginLogoutService failed to start after {maxRetries} attempts: {ex}",
                            EventLogEntryType.Error, 1002);
                        try { _checkpointService.SaveStopCheckpoint(DateTime.UtcNow.AddSeconds(-5)); }
                        catch (Exception checkpointEx)
                        {
                            SafeWriteEventLog("Application",
                                $"[STARTUP] Failed to save stop checkpoint after startup exhaustion: {checkpointEx.Message}",
                                EventLogEntryType.Warning, 1002);
                        }
                        ExitCode = 1;
                        try { Stop(); }
                        catch (Exception stopEx)
                        {
                            SafeWriteEventLog("Application",
                                $"[STARTUP] Failed to stop service after startup exhaustion: {stopEx.Message}",
                                EventLogEntryType.Warning, 1002);
                        }
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
                var (qcOutput, qcExitCode) = RunSc($"qc \"{serviceName}\"");
                if (qcExitCode != 0)
                {
                    SafeWriteEventLog("Application",
                        $"[RESILIENCE] sc qc exit code {qcExitCode}. Output: '{qcOutput.Trim()}'",
                        EventLogEntryType.Warning, 1064);
                }

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

                var (configOutput, configExitCode) = RunSc($"config \"{serviceName}\" start= auto");
                if (configExitCode != 0)
                {
                    SafeWriteEventLog("Application",
                        $"[RESILIENCE] sc config exit code {configExitCode}. Output: '{configOutput.Trim()}'",
                        EventLogEntryType.Warning, 1064);
                }

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
        ///   reset= 3600 (counter reset setelah 1 jam normal)
        ///   actions= restart/5000/restart/30000/restart/60000/restart/120000
        /// </summary>
        private void EnsureFailureActions(string serviceName)
        {
            try
            {
                var (qfailureOutput, qfailureExitCode) = RunSc($"qfailure \"{serviceName}\"");
                if (qfailureExitCode != 0)
                {
                    SafeWriteEventLog("Application",
                        $"[RESILIENCE] sc qfailure exit code {qfailureExitCode}. Output: '{qfailureOutput.Trim()}'",
                        EventLogEntryType.Warning, 1068);
                }

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

                var (failureOutput, failureExitCode) = RunSc(
                    $"failure \"{serviceName}\" reset= 3600 " +
                    $"actions= restart/5000/restart/30000/restart/60000/restart/120000");
                if (failureExitCode != 0)
                {
                    SafeWriteEventLog("Application",
                        $"[RESILIENCE] sc failure exit code {failureExitCode}. Output: '{failureOutput.Trim()}'",
                        EventLogEntryType.Warning, 1068);
                }

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
        /// Jalankan sc.exe dengan argumen tertentu, return stdout+stderr + exit code.
        /// Timeout 10 detik — sc.exe lokal hampir selalu selesai dalam < 1 detik.
        /// </summary>
        private static (string Output, int ExitCode) RunSc(string arguments)
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
            bool exited = process.WaitForExit(10_000); // timeout 10 detik
            int exitCode = exited ? process.ExitCode : -1;
            return (output, exitCode);
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
                    _checkpointService.SaveStopCheckpoint(DateTime.UtcNow.AddMinutes(-1));
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
                _checkpointService.SaveStopCheckpoint(DateTime.UtcNow.AddMinutes(-1));
                e.SetObserved();
            }
            catch
            {
                // Never throw from global exception hooks.
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
                    _checkpointService.SaveStopCheckpoint(DateTime.UtcNow);
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

        private static void SafeWriteEventLogAlways(string source, string message, EventLogEntryType type, int eventId)
        {
            try
            {
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
            // Startup index-load info detail (warning/error tetap pakai ID lain agar selalu tampil)
            1058,
            // Config validation: "OK" confirmation — verbose only.
            // Error/warning IDs (1070, 1071, 1072, 1073) sengaja TIDAK di sini agar selalu tampil.
            1075,
            // Health check (Security): "OK" / info detail — verbose only.
            // Warning/error IDs (1079, 1081, 1084, 1085) sengaja TIDAK di sini — selalu tampil.
            // 1079 = subscription silent warning → selalu tampil (kondisi abnormal)
            // 1080 = re-subscribe OK → verbose (sukses, tidak perlu alert)
            // 1081 = re-subscribe attempt failed → selalu tampil (warning)
            // 1082 = mini-replay start → verbose
            // 1083 = mini-replay selesai → verbose
            // 1084 = mini-replay error → selalu tampil
            // 1085 = health check task error → selalu tampil
            // Health check (System):
            // 1086 = subscription silent warning → selalu tampil
            // 1087 = re-subscribe OK → verbose
            // 1088 = re-subscribe attempt failed → selalu tampil (warning)
            // 1089 = mini-replay start/done → verbose
            // 1090 = health check fatal → selalu tampil
            // 1098 = external heartbeat OK → verbose
            // 1092 = supervisor/watchdog restarted confirmation → verbose
            // 1096 = power resume/suspend info detail → verbose
            1080, 1082, 1083, 1087, 1089, 1092, 1096, 1098,
            // Debug system event parsing — semua [DBG-*]
            2001, 2002, 2003, 2004, 2005, 2006, 2007, 2010, 2011, 2012, 2020, 2021, 1041,
            // Debug fallback resolution detail — [DBG-1074] resolved
            2013,
            // Debug RawEventStore fallback — [DBG-4624], [DBG-GetMRU], [DBG-42], [DBG-4634]
            // 2026 = unresolved 4647 queued as pending (debug process detail)
            2026, 2028, 2031, 2032, 2033,
            // Admin correlation process detail (info-only)
            // 2043 (warning: lookup failure) sengaja TIDAK di sini agar selalu tampil.
            2041, 2042,
            // 4634 deferred retry pipeline — [4634-RETRY] / [4634-FILTER]
            // 2050 = deferring (info, verbose — terjadi setiap 4634 saat startup)
            // 2051 = queue full warning → TIDAK di sini (selalu tampil)
            // 2052 = drain start/selesai summary → verbose (proses internal)
            // 2053 = expired/retry-limit fallback warning → TIDAK di sini (selalu tampil)
            // 2054 = per-event reprocess progress → verbose (terlalu sering di production)
            // 2055 = error saat reprocess → TIDAK di sini (selalu tampil)
            // 2056 = warmup masih berlangsung saat retry → TIDAK di sini (warning, selalu tampil)
            // 2057 = drain dibatalkan → TIDAK di sini (selalu tampil)
            2050, 2052, 2054,
            // SharePoint summary detail
            3001, 3002, 3003, 3004, 3005, 3007, 3008,
            3010, 3011, 3012, 3013, 3014, 3015, 3016, 3017, 3018, 3021, 3022,
            // 3032 = cross-device later time (info, verbose — terjadi setiap ada multi-device shutdown)
            3032,
            // Dispatch detail (per-event, terlalu sering di production)
            4002, 4003, 4004, 4005, 4006, 4007, 4008, 4009, 4010,
            // Event 42 last-resort promotion
            4011,
            // RAW insert success detail
            4020, 4021, 4022, 4025,
            // Cleanup progress detail
            // 5007 = dictionary prune info
            5001, 5002, 5003, 5006, 5007,
            // Catatan: 0 (start), 1048 (ready), 1050 (OnStop), 1051 (OnShutdown)
            // sengaja TIDAK ada di sini — lifecycle events selalu tampil.
        };

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
                        string? linkedLogonId = raw.LinkedLogonId;
                        string linkedSuffix = string.IsNullOrEmpty(linkedLogonId)
                            ? string.Empty
                            : $" linkedLogonId={linkedLogonId}";

                        // Register LogonId utama + LinkedLogonId (split-token) dari disk.
                        _adminCorrelationService.RegisterAdminSession(
                            computerName,
                            raw.LogonId,
                            linkedLogonId,
                            $"[ADMIN] Admin session re-hydrated from RawStore: " +
                            $"user={raw.Username} logonId={raw.LogonId}{linkedSuffix} computer={computerName}");
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

                    // Temporal dedup: deteksi 4634 yang fire dalam 30 detik setelah 4624
                    // (stale session close saat unlock/CachedInteractive) — sama dengan live path.
                    //
                    // FIX: sebelumnya di-drop total (return). Sekarang raw-only dispatch:
                    // tetap masuk raw list SharePoint sebagai audit trail, tapi tidak update
                    // summary via status="STALE_SESSION_CLOSE".
                    // Is4634StaleAsync cek dua sumber: queue in-memory DAN RawEventStore disk.
                    const int staleWindowSecondsRaw = 30;
                    bool isStaleRaw = await Is4634StaleAsync(
                        username,
                        computerName,
                        workDate4634raw,
                        eventTime,
                        staleWindowSecondsRaw);
                    if (isStaleRaw)
                    {
                        SafeWriteEventLog("Attendance-Service",
                            $"[DBG-4634] RawReplay stale session close — raw-only dispatch, summary skipped: " +
                            $"4634 fired within {staleWindowSecondsRaw}s of 4624. " +
                            $"user='{username}' computer='{computerName}' time={eventTime:O}",
                            EventLogEntryType.Information, 2033);

                        // Raw-only: dispatch ke raw list tapi tidak update summary.
                        await ProcessEvent(
                            4634, username, eventTime, computerName,
                            "Security", 0, null, writeRawRecord,
                            usernameResolutionSource: "Direct",
                            isFallback: true,
                            fallbackSource: "Event4634_StaleSessionClose",
                            status: "STALE_SESSION_CLOSE");
                        return;
                    }

                    bool has4647raw = await eventQueue.Has4647InQueueAsync(
                        username,
                        computerName,
                        workDate4634raw);
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
            _heartbeatListId = config["SharePointSettings:HeartbeatListId"];

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
            string? heartbeatListId = config["SharePointSettings:HeartbeatListId"];

            Critical("SharePointSettings:SiteId",  siteId);
            Critical("SharePointSettings:ListId",  listId);

            // SummaryListId opsional tapi kalau kosong fitur Summary nonaktif
            Warn("SharePointSettings:SummaryListId", summaryListId,
                "Fitur Summary (ClockIn/ClockOut harian) tidak akan aktif.");

            Warn("SharePointSettings:HeartbeatListId", heartbeatListId,
                "SharePointSettings:HeartbeatListId kosong — fitur external heartbeat monitoring tidak aktif.");

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

        protected override void OnStop()
        {
            // FIX [ADMIN-GATE]: Service restart (SCM / manual / sc failure recovery).
            // Hanya flush in-memory cache — TIDAK menghapus boot-session-id.txt.
            // GUID dipertahankan agar re-hydrate dari RawEventStore pada startup berikutnya
            // menggunakan key yang sama sehingga admin correlation lookup tetap match.
            _adminCorrelationService.ClearAdminSessionCache();
            HandleServiceStopping("OnStop", 1050);
        }

        /// <summary>
        /// Called by SCM during Windows system shutdown/restart (requires CanShutdown = true).
        /// OnStop() is NOT guaranteed to be called in that scenario.
        /// </summary>
        protected override void OnShutdown()
        {
            // FIX [ADMIN-GATE]: Windows shutdown / reboot nyata.
            // Hapus boot-session-id.txt agar sesi Windows baru mendapat GUID baru —
            // sesi lama tidak boleh ter-carry-over lintas reboot.
            _adminCorrelationService.InvalidateBootSessionOnWindowsShutdown();
            HandleServiceStopping("OnShutdown", 1051);
        }

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
                        EventLogEntryType.Information, 1096);

                    long resumeTicks = DateTime.UtcNow.Ticks;

                    // Reset Security log counters — startup probe Security akan aktif kembali
                    Interlocked.Exchange(ref _subscriptionEnabledTicksUtc, resumeTicks);
                    Interlocked.Exchange(ref _securityProbeEpochTicks,     resumeTicks);
                    Interlocked.Exchange(ref _lastSecurityEventTicksUtc,   DateTime.MinValue.Ticks);

                    // Reset System log counters — health check baseline pasca-resume
                    Interlocked.Exchange(ref _systemSubscriptionEnabledTicksUtc, resumeTicks);
                    Interlocked.Exchange(ref _lastSystemEventTicksUtc,           DateTime.MinValue.Ticks);

                    // Reset watchdog heartbeat baselines untuk task yang MASIH running.
                    //
                    // Masalah: saat PC resume dari sleep/hibernate, task-task background (queue
                    // processor, cleanup, heartbeat, dll.) tidak di-restart — mereka dilanjutkan
                    // dari state sebelum suspend. Heartbeat tick mereka terakhir diperbarui sebelum
                    // suspend, sehingga watchdog mengukur elapsed = durasi sleep (bisa 8-15+ jam).
                    // Ini menyebabkan watchdog langsung restart semua task di check berikutnya
                    // (~5 menit) meskipun task sebenarnya masih aktif dan akan heartbeat sendiri
                    // segera setelah resume.
                    //
                    // Fix: reset baseline ke 'now' HANYA untuk task yang !IsTaskStopped.
                    // Task yang sudah crash/selesai sebelum sleep dibiarkan stale — watchdog akan
                    // mendeteksi dan me-restart mereka seperti biasa (perilaku yang diinginkan).
                    // Task yang masih running diberi grace period = timeout normal mereka dari
                    // titik resume, bukan dari sebelum suspend.
                    if (!IsTaskStopped(queueTask))
                        Interlocked.Exchange(ref _lastQueueProcessorHeartbeatUtc, resumeTicks);
                    if (!IsTaskStopped(cleanupTask))
                        Interlocked.Exchange(ref _lastCleanupHeartbeatUtc,        resumeTicks);
                    if (!IsTaskStopped(securityHealthTask))
                        Interlocked.Exchange(ref _lastSecurityHealthHeartbeatUtc, resumeTicks);
                    if (!IsTaskStopped(systemHealthTask))
                        Interlocked.Exchange(ref _lastSystemHealthHeartbeatUtc,   resumeTicks);
                    if (!IsTaskStopped(heartbeatTask))
                        Interlocked.Exchange(ref _lastHeartbeatTaskHeartbeatUtc,  resumeTicks);

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
                            _ = await ResubscribeSystemLogAndMiniReplayAsync(replayFrom, replayTo, 3, ct);
                        }
                        catch (OperationCanceledException) { /* service stopping */ }
                        catch (Exception ex)
                        {
                            SafeWriteEventLog("Application",
                                $"[POWER] Resume re-subscribe error: {ex.Message}",
                                EventLogEntryType.Warning, 1097);
                        }
                    }, ct);
                }
                else if (powerStatus == PowerBroadcastStatus.Suspend)
                {
                    // Simpan checkpoint sebelum suspend — kalau PC tidak resume normal
                    // (misal battery dead), replay berikutnya punya referensi yang benar.
                    SafeWriteEventLog("Application",
                        "[POWER] Suspend detected — saving stop checkpoint.",
                        EventLogEntryType.Information, 1096);

                    _checkpointService.SaveStopCheckpoint(DateTime.UtcNow.AddSeconds(-5));
                }
            }
            catch (Exception ex)
            {
                SafeWriteEventLog("Application",
                    $"[POWER] OnPowerEvent error ({powerStatus}): {ex.Message}",
                    EventLogEntryType.Warning, 1097);
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

                // FIX [ADMIN-GATE]: InvalidateBootSession / ClearAdminSessionCache sudah
                // dipanggil secara eksplisit di OnStop() dan OnShutdown() masing-masing,
                // dengan method yang tepat sesuai konteks. Tidak perlu dipanggil lagi di sini.

                // ── Step 1: Request extra shutdown time from SCM immediately.
                // Windows system shutdown gives services only ~5 seconds by default.
                // RequestAdditionalTime tells SCM we need more — prevents premature kill.
                RequestAdditionalTime(8000);

                // ── Step 2: Save checkpoint FIRST, before anything else.
                // Hanya tulis kalau kandidat lebih baru dari checkpoint yang sudah ada —
                // jangan mundurkan checkpoint yang sudah akurat dari per-event atau heartbeat.
                // Now - 5 detik sebagai buffer kecil agar event yang sedang in-flight tidak terpotong.
                DateTime candidate = DateTime.UtcNow.AddSeconds(-5);
                DateTime? existing = _checkpointService.TryLoadStopCheckpoint();
                DateTime stopCheckpoint = (existing.HasValue && existing.Value > candidate)
                    ? existing.Value
                    : candidate;

                SafeWriteEventLog("Application",
                    $"{caller}: saving checkpoint {stopCheckpoint:O} " +
                    $"(candidate={candidate:O} existing={existing?.ToString("O") ?? "(none)"})",
                    EventLogEntryType.Information, 1018);

                _checkpointService.SaveStopCheckpoint(stopCheckpoint);

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

                // [SPRINT] Flush shutdown events sebelum cancel token — hanya saat shutdown sistem nyata.
                // Untuk OnStop (restart/manual), replay startup berikutnya sudah cukup.
                if (caller == "OnShutdown")
                {
                    checkpointHeartbeatTimer?.Dispose();
                    checkpointHeartbeatTimer = null;

                    TryFlushShutdownEventsOnStopAsync().GetAwaiter().GetResult();
                }

                cancellationTokenSource?.Cancel();
                StopBackgroundTasks();

                // Dispose heartbeat timer untuk OnStop path (OnShutdown sudah dispose di atas).
                if (caller != "OnShutdown")
                {
                    checkpointHeartbeatTimer?.Dispose();
                    checkpointHeartbeatTimer = null;
                }

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
                StartBackgroundTasks(cancellationToken);

                lock (_backgroundTaskLock)
                {
                    if (IsTaskStopped(systemHealthTask))
                        systemHealthTask = Task.Run(() => SystemLogSubscriptionHealthCheckTask(cancellationToken), cancellationToken);
                }

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

        private void StartBackgroundTasks(CancellationToken cancellationToken)
        {
            if (cancellationToken.IsCancellationRequested)
                return;

            lock (_backgroundTaskLock)
            {
                if (cancellationToken.IsCancellationRequested)
                    return;

                if (IsTaskStopped(cleanupTask))
                    StartCleanupTask(cancellationToken);
                if (IsTaskStopped(queueTask))
                    StartQueueTask(cancellationToken);
                if (IsTaskStopped(securityHealthTask))
                    StartSecurityHealthTask(cancellationToken);
                if (IsTaskStopped(systemHealthTask))
                    StartSystemHealthTask(cancellationToken);
                if (IsTaskStopped(heartbeatTask))
                    StartHeartbeatTask(cancellationToken);

                if (IsTaskStopped(supervisorTask))
                    supervisorTask = Task.Run(() => BackgroundTaskSupervisorLoop(cancellationToken), cancellationToken);
                if (IsTaskStopped(watchdogTask))
                    watchdogTask = Task.Run(() => InternalWatchdogTask(cancellationToken), cancellationToken);
            }

            StartSupervisorWatchdogTimer(cancellationToken);
        }

        private void StartSupervisorWatchdogTimer(CancellationToken cancellationToken)
        {
            if (cancellationToken.IsCancellationRequested)
                return;

            _supervisorWatchdogTimer?.Dispose();
            _supervisorWatchdogTimer = new Timer(_ =>
            {
                if (cancellationToken.IsCancellationRequested)
                    return;

                try
                {
                    lock (_backgroundTaskLock)
                    {
                        if (cancellationToken.IsCancellationRequested)
                            return;

                        if (IsTaskStopped(supervisorTask))
                        {
                            SafeWriteEventLog("Application",
                                "[SUPERVISOR-GUARD] supervisorTask stopped — restarting.",
                                EventLogEntryType.Warning, 1091);
                            supervisorTask = Task.Run(
                                () => BackgroundTaskSupervisorLoop(cancellationToken),
                                cancellationToken);
                        }

                        if (IsTaskStopped(watchdogTask))
                        {
                            SafeWriteEventLog("Application",
                                "[SUPERVISOR-GUARD] watchdogTask stopped — restarting.",
                                EventLogEntryType.Warning, 1091);
                            watchdogTask = Task.Run(
                                () => InternalWatchdogTask(cancellationToken),
                                cancellationToken);
                        }
                    }
                }
                catch (Exception ex)
                {
                    SafeWriteEventLog("Application",
                        $"[SUPERVISOR-GUARD] Timer check failed: {ex.Message}",
                        EventLogEntryType.Warning, 1093);
                }
            }, null, TimeSpan.FromMinutes(2), TimeSpan.FromMinutes(2));
        }

        private static bool IsTaskStopped(Task? task)
            => task == null || task.IsCompleted || task.IsCanceled || task.IsFaulted;

        private CancellationToken CreateLinkedToken(ref CancellationTokenSource? taskCts, CancellationToken serviceToken)
        {
            taskCts?.Cancel();
            taskCts?.Dispose();
            taskCts = CancellationTokenSource.CreateLinkedTokenSource(serviceToken);
            return taskCts.Token;
        }

        private bool StartCleanupTask(CancellationToken serviceToken)
            => TryStartTask(
                "Cleanup task",
                ref cleanupTask,
                ref _cleanupTaskCts,
                ref _lastCleanupHeartbeatUtc,
                CleanupOldRecordsTask,
                serviceToken);

        private bool StartQueueTask(CancellationToken serviceToken)
            => TryStartTask(
                "Queue processor task",
                ref queueTask,
                ref _queueTaskCts,
                ref _lastQueueProcessorHeartbeatUtc,
                ProcessQueuedEventsTask,
                serviceToken);

        private bool StartSecurityHealthTask(CancellationToken serviceToken)
            => TryStartTask(
                "Security health task",
                ref securityHealthTask,
                ref _securityHealthTaskCts,
                ref _lastSecurityHealthHeartbeatUtc,
                SecurityLogSubscriptionHealthCheckTask,
                serviceToken);

        private bool StartSystemHealthTask(CancellationToken serviceToken)
            => TryStartTask(
                "System health task",
                ref systemHealthTask,
                ref _systemHealthTaskCts,
                ref _lastSystemHealthHeartbeatUtc,
                SystemLogSubscriptionHealthCheckTask,
                serviceToken);

        private bool StartHeartbeatTask(CancellationToken serviceToken)
            => TryStartTask(
                "Heartbeat task",
                ref heartbeatTask,
                ref _heartbeatTaskCts,
                ref _lastHeartbeatTaskHeartbeatUtc,
                HeartbeatWriterTask,
                serviceToken);

        private bool TryStartTask(
            string taskName,
            ref Task? taskField,
            ref CancellationTokenSource? taskCts,
            ref long heartbeatTicks,
            Func<CancellationToken, Task> taskFactory,
            CancellationToken cancellationToken)
        {
            if (cancellationToken.IsCancellationRequested)
                return false;

            try
            {
                CancellationToken linkedToken = CreateLinkedToken(ref taskCts, cancellationToken);
                Interlocked.Exchange(ref heartbeatTicks, DateTime.UtcNow.Ticks);
                taskField = Task.Run(() => taskFactory(linkedToken), linkedToken);
                return true;
            }
            catch (Exception ex)
            {
                SafeWriteEventLog("Application",
                    $"[SUPERVISOR] Failed to start {taskName}: {ex.Message}",
                    EventLogEntryType.Error, 1093);
                return false;
            }
        }

        private static string DescribeTaskState(Task? task)
        {
            if (task == null)
                return "not started";
            if (task.IsFaulted)
                return "faulted";
            if (task.IsCanceled)
                return "canceled";
            if (task.IsCompleted)
                return "completed";
            return "running";
        }

        private void RecordRestartAttempt(string taskName, Queue<DateTime> history, CancellationToken cancellationToken)
        {
            if (cancellationToken.IsCancellationRequested)
                return;

            try
            {
                DateTime now = DateTime.UtcNow;
                history.Enqueue(now);
                while (history.Count > 0 && now - history.Peek() > RestartFailureWindow)
                    history.Dequeue();

                if (history.Count > RestartFailureThreshold)
                {
                    SafeWriteEventLog("Application",
                        $"[FATAL] {taskName} restarted {history.Count} times within " +
                        $"{RestartFailureWindow.TotalMinutes:F0} minutes — failing fast to trigger SCM recovery.",
                        EventLogEntryType.Error, 1095);
                    Environment.FailFast($"{taskName} restart instability detected.");
                }
            }
            catch (Exception ex)
            {
                SafeWriteEventLog("Application",
                    $"[SUPERVISOR] Restart history tracking failed for {taskName}: {ex.Message}",
                    EventLogEntryType.Warning, 1093);
            }
        }

        private void RestartStoppedTask(
            string taskName,
            ref Task? taskField,
            ref CancellationTokenSource? taskCts,
            ref long heartbeatTicks,
            Func<CancellationToken, Task> taskFactory,
            Queue<DateTime> restartHistory,
            CancellationToken cancellationToken)
        {
            if (cancellationToken.IsCancellationRequested)
                return;

            if (!IsTaskStopped(taskField))
                return;

            lock (_backgroundTaskLock)
            {
                if (cancellationToken.IsCancellationRequested)
                    return;

                if (!IsTaskStopped(taskField))
                    return;

                string reason = DescribeTaskState(taskField);
                SafeWriteEventLog("Application",
                    $"[SUPERVISOR] {taskName} stopped ({reason}) — restarting.",
                    EventLogEntryType.Warning, 1091);

                bool started = TryStartTask(
                    taskName,
                    ref taskField,
                    ref taskCts,
                    ref heartbeatTicks,
                    taskFactory,
                    cancellationToken);
                if (started)
                {
                    SafeWriteEventLog("Application",
                        $"[SUPERVISOR] {taskName} restarted.",
                        EventLogEntryType.Information, 1092);
                }

                RecordRestartAttempt(taskName, restartHistory, cancellationToken);
            }
        }

        private void RestartStalledTask(
            string taskName,
            TimeSpan timeout,
            ref long heartbeatTicks,
            ref Task? taskField,
            ref CancellationTokenSource? taskCts,
            Func<CancellationToken, Task> taskFactory,
            Queue<DateTime> restartHistory,
            CancellationToken cancellationToken)
        {
            if (cancellationToken.IsCancellationRequested)
                return;

            DateTime nowUtc = DateTime.UtcNow;
            long lastTicks = Interlocked.Read(ref heartbeatTicks);
            TimeSpan elapsed = lastTicks == DateTime.MinValue.Ticks
                ? TimeSpan.MaxValue
                : nowUtc - new DateTime(lastTicks, DateTimeKind.Utc);
            if (elapsed <= timeout)
                return;

            lock (_backgroundTaskLock)
            {
                if (cancellationToken.IsCancellationRequested)
                    return;

                long latestTicks = Interlocked.Read(ref heartbeatTicks);
                TimeSpan latestElapsed = latestTicks == DateTime.MinValue.Ticks
                    ? TimeSpan.MaxValue
                    : DateTime.UtcNow - new DateTime(latestTicks, DateTimeKind.Utc);
                if (latestElapsed <= timeout)
                    return;

                string ageLabel = latestTicks == DateTime.MinValue.Ticks
                    ? "no heartbeat"
                    : $"{latestElapsed.TotalMinutes:F0} min";

                SafeWriteEventLog("Application",
                    $"[WATCHDOG] {taskName} heartbeat stale ({ageLabel}, timeout={timeout.TotalMinutes:F0} min) — restarting.",
                    EventLogEntryType.Warning, 1094);

                try
                {
                    taskCts?.Cancel();
                }
                catch (Exception cancelEx)
                {
                    SafeWriteEventLog("Application",
                        $"[WATCHDOG] {taskName} cancel failed during stalled restart: {cancelEx.Message}",
                        EventLogEntryType.Warning, 1094);
                }

                Task? previousTask = taskField;
                if (previousTask != null && !IsTaskStopped(previousTask))
                {
                    try
                    {
                        bool stoppedInGrace = previousTask.Wait(TimeSpan.FromSeconds(5));
                        if (!stoppedInGrace)
                        {
                            SafeWriteEventLog("Application",
                                $"[WATCHDOG] {taskName} did not stop within 5s grace period — forcing restart with new token.",
                                EventLogEntryType.Warning, 1094);
                        }
                    }
                    catch (Exception waitEx)
                    {
                        SafeWriteEventLog("Application",
                            $"[WATCHDOG] {taskName} wait-for-stop failed: {waitEx.Message}. Forcing restart.",
                            EventLogEntryType.Warning, 1094);
                    }
                }

                bool started = TryStartTask(
                    taskName,
                    ref taskField,
                    ref taskCts,
                    ref heartbeatTicks,
                    taskFactory,
                    cancellationToken);

                if (started)
                {
                    SafeWriteEventLog("Application",
                        $"[WATCHDOG] {taskName} restarted.",
                        EventLogEntryType.Information, 1092);
                }

                RecordRestartAttempt(taskName, restartHistory, cancellationToken);
            }
        }

        private async Task BackgroundTaskSupervisorLoop(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(TimeSpan.FromMinutes(1), cancellationToken);

                    RestartStoppedTask(
                        "Cleanup task",
                        ref cleanupTask,
                        ref _cleanupTaskCts,
                        ref _lastCleanupHeartbeatUtc,
                        CleanupOldRecordsTask,
                        _cleanupRestartHistory,
                        cancellationToken);
                    RestartStoppedTask(
                        "Queue processor task",
                        ref queueTask,
                        ref _queueTaskCts,
                        ref _lastQueueProcessorHeartbeatUtc,
                        ProcessQueuedEventsTask,
                        _queueRestartHistory,
                        cancellationToken);
                    RestartStoppedTask(
                        "Security health task",
                        ref securityHealthTask,
                        ref _securityHealthTaskCts,
                        ref _lastSecurityHealthHeartbeatUtc,
                        SecurityLogSubscriptionHealthCheckTask,
                        _securityHealthRestartHistory,
                        cancellationToken);
                    RestartStoppedTask(
                        "System health task",
                        ref systemHealthTask,
                        ref _systemHealthTaskCts,
                        ref _lastSystemHealthHeartbeatUtc,
                        SystemLogSubscriptionHealthCheckTask,
                        _systemHealthRestartHistory,
                        cancellationToken);
                    RestartStoppedTask(
                        "Heartbeat task",
                        ref heartbeatTask,
                        ref _heartbeatTaskCts,
                        ref _lastHeartbeatTaskHeartbeatUtc,
                        HeartbeatWriterTask,
                        _heartbeatRestartHistory,
                        cancellationToken);
                }
                catch (TaskCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    SafeWriteEventLog("Application",
                        $"[SUPERVISOR] BackgroundTaskSupervisorLoop error: {ex.Message}",
                        EventLogEntryType.Error, 1093);
                    try { await Task.Delay(TimeSpan.FromSeconds(30), cancellationToken); }
                    catch (TaskCanceledException) { break; }
                }
            }
        }

        private async Task InternalWatchdogTask(CancellationToken cancellationToken)
        {
            TimeSpan queueTimeout = TimeSpan.FromMinutes(10);
            TimeSpan securityTimeout = TimeSpan.FromMinutes(15);
            TimeSpan systemTimeout = TimeSpan.FromMinutes(30);
            TimeSpan cleanupTimeout = TimeSpan.FromHours(6);
            TimeSpan heartbeatTimeout = TimeSpan.FromHours(1);

            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(TimeSpan.FromMinutes(5), cancellationToken);

                    RestartStalledTask(
                        "Queue processor task",
                        queueTimeout,
                        ref _lastQueueProcessorHeartbeatUtc,
                        ref queueTask,
                        ref _queueTaskCts,
                        ProcessQueuedEventsTask,
                        _queueRestartHistory,
                        cancellationToken);
                    RestartStalledTask(
                        "Security health task",
                        securityTimeout,
                        ref _lastSecurityHealthHeartbeatUtc,
                        ref securityHealthTask,
                        ref _securityHealthTaskCts,
                        SecurityLogSubscriptionHealthCheckTask,
                        _securityHealthRestartHistory,
                        cancellationToken);
                    RestartStalledTask(
                        "System health task",
                        systemTimeout,
                        ref _lastSystemHealthHeartbeatUtc,
                        ref systemHealthTask,
                        ref _systemHealthTaskCts,
                        SystemLogSubscriptionHealthCheckTask,
                        _systemHealthRestartHistory,
                        cancellationToken);
                    RestartStalledTask(
                        "Cleanup task",
                        cleanupTimeout,
                        ref _lastCleanupHeartbeatUtc,
                        ref cleanupTask,
                        ref _cleanupTaskCts,
                        CleanupOldRecordsTask,
                        _cleanupRestartHistory,
                        cancellationToken);
                    RestartStalledTask(
                        "Heartbeat task",
                        heartbeatTimeout,
                        ref _lastHeartbeatTaskHeartbeatUtc,
                        ref heartbeatTask,
                        ref _heartbeatTaskCts,
                        HeartbeatWriterTask,
                        _heartbeatRestartHistory,
                        cancellationToken);
                }
                catch (TaskCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    SafeWriteEventLog("Application",
                        $"[WATCHDOG] InternalWatchdogTask error: {ex.Message}",
                        EventLogEntryType.Error, 1093);
                    try { await Task.Delay(TimeSpan.FromSeconds(30), cancellationToken); }
                    catch (TaskCanceledException) { break; }
                }
            }
        }

        private void StopBackgroundTasks()
        {
            lock (_backgroundTaskLock)
            {
                CancelTask(ref _cleanupTaskCts);
                CancelTask(ref _queueTaskCts);
                CancelTask(ref _securityHealthTaskCts);
                CancelTask(ref _systemHealthTaskCts);
                CancelTask(ref _heartbeatTaskCts);
                _supervisorWatchdogTimer?.Dispose();
                _supervisorWatchdogTimer = null;

                cleanupTask = null;
                queueTask = null;
                securityHealthTask = null;
                systemHealthTask = null;
                heartbeatTask = null;
                supervisorTask = null;
                watchdogTask = null;
            }
        }

        private static void CancelTask(ref CancellationTokenSource? taskCts)
        {
            if (taskCts == null)
                return;

            try { taskCts.Cancel(); } catch { }
            try { taskCts.Dispose(); } catch { }
            taskCts = null;
        }

        /// <summary>
        /// Sprint saat OnShutdown: flush shutdown events dari queue sebelum token global di-cancel.
        /// Best-effort — jika network sudah mati, item tetap di queue untuk replay saat boot berikutnya.
        /// </summary>
        private async Task TryFlushShutdownEventsOnStopAsync()
        {
            static bool IsShutdownEventId(int id)
                => id == 4647 || id == 1074 || id == 6006 || id == 4634 || id == 42;

            const int sprintTimeoutMs      = 3000;
            const int sprintTotalBudgetMs  = 5500;

            var sprintDeadline = DateTime.UtcNow.AddMilliseconds(sprintTotalBudgetMs);
            using var sprintCts = new CancellationTokenSource(sprintTotalBudgetMs);
            CancellationToken sprintToken = sprintCts.Token;

            try
            {
                List<QueuedAttendanceEvent> allItems = await eventQueue
                    .GetAllAsync(sprintToken)
                    .ConfigureAwait(false);

                var shutdownItems = allItems
                    .Where(x => IsShutdownEventId(x.EventId)
                                && !(x.RawRecordDispatched && x.SummaryDispatched))
                    .OrderByDescending(x => GetShutdownEventPriority(x.EventId, x.EventType ?? string.Empty))
                    .ThenByDescending(x => x.EventTime)
                    .ToList();

                if (shutdownItems.Count == 0)
                {
                    SafeWriteEventLog("Attendance-Service",
                        "[SHUTDOWN-SPRINT] Tidak ada shutdown event pending — sprint dilewati.",
                        EventLogEntryType.Information, 1051);
                    return;
                }

                SafeWriteEventLog("Attendance-Service",
                    $"[SHUTDOWN-SPRINT] Sprint dimulai: {shutdownItems.Count} item(s). " +
                    $"budget={sprintTotalBudgetMs}ms timeoutPerItem={sprintTimeoutMs}ms",
                    EventLogEntryType.Information, 1051);

                int flushed = 0, failed = 0, skipped = 0;

                foreach (QueuedAttendanceEvent item in shutdownItems)
                {
                    TimeSpan remaining = sprintDeadline - DateTime.UtcNow;
                    if (remaining.TotalMilliseconds < 500 || sprintToken.IsCancellationRequested)
                    {
                        SafeWriteEventLog("Attendance-Service",
                            $"[SHUTDOWN-SPRINT] Budget habis — stop. flushed={flushed} failed={failed}",
                            EventLogEntryType.Warning, 1051);
                        break;
                    }

                    int effectiveTimeout = (int)Math.Min(sprintTimeoutMs, remaining.TotalMilliseconds - 200);
                    if (effectiveTimeout < 500) { skipped++; continue; }

                    using var itemCts = CancellationTokenSource.CreateLinkedTokenSource(sprintToken);
                    itemCts.CancelAfter(effectiveTimeout);

                    Interlocked.Increment(ref activeDispatchCount);
                    try
                    {
                        bool sent = await TryDispatchQueuedEventAsync(item, itemCts.Token)
                            .ConfigureAwait(false);

                        if (sent)
                        {
                            await eventQueue.RemoveByIdAsync(item.QueueId, sprintToken)
                                .ConfigureAwait(false);
                            flushed++;
                            SafeWriteEventLog("Attendance-Service",
                                $"[SHUTDOWN-SPRINT] Flushed: eventId={item.EventId} user={item.Username} " +
                                $"computer={item.ComputerName} time={item.EventTime:O}",
                                EventLogEntryType.Information, 1051);
                        }
                        else
                        {
                            failed++;
                            SafeWriteEventLog("Attendance-Service",
                                $"[SHUTDOWN-SPRINT] Dispatch failed — retained for replay: " +
                                $"eventId={item.EventId} user={item.Username} error={item.LastDispatchError}",
                                EventLogEntryType.Warning, 1051);
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        failed++;
                        SafeWriteEventLog("Attendance-Service",
                            $"[SHUTDOWN-SPRINT] Timeout — retained for replay: " +
                            $"eventId={item.EventId} user={item.Username} queueId={item.QueueId}",
                            EventLogEntryType.Warning, 1051);
                    }
                    catch (Exception ex)
                    {
                        failed++;
                        SafeWriteEventLog("Application",
                            $"[SHUTDOWN-SPRINT] Error: eventId={item.EventId} user={item.Username} — {ex.Message}",
                            EventLogEntryType.Warning, 1051);
                    }
                    finally
                    {
                        Interlocked.Decrement(ref activeDispatchCount);
                    }
                }

                SafeWriteEventLog("Attendance-Service",
                    $"[SHUTDOWN-SPRINT] Selesai: flushed={flushed} failed={failed} skipped={skipped}. " +
                    "Item yang gagal akan di-retry saat startup berikutnya.",
                    EventLogEntryType.Information, 1051);
            }
            catch (OperationCanceledException)
            {
                SafeWriteEventLog("Attendance-Service",
                    "[SHUTDOWN-SPRINT] Dibatalkan oleh total budget timeout.",
                    EventLogEntryType.Warning, 1051);
            }
            catch (Exception ex)
            {
                SafeWriteEventLog("Application",
                    $"[SHUTDOWN-SPRINT] Sprint error (non-fatal): {ex.Message}",
                    EventLogEntryType.Warning, 1051);
            }
        }

        // ─── Queue processor ─────────────────────────────────────────────────────

        private async Task ProcessQueuedEventsTask(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                Interlocked.Exchange(ref _lastQueueProcessorHeartbeatUtc, DateTime.UtcNow.Ticks);
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
                        sent = await TryDispatchQueuedEventAsync(next, cancellationToken);
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

            long lastProbeEpochHandled = DateTime.MinValue.Ticks;

            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    bool useFastRetry = _resubscribeFailed;
                    int delaySeconds = useFastRetry ? 5 : checkIntervalSeconds;
                    await Task.Delay(TimeSpan.FromSeconds(delaySeconds), cancellationToken);
                    if (useFastRetry)
                        _resubscribeFailed = false;

                    Interlocked.Exchange(ref _lastSecurityHealthHeartbeatUtc, DateTime.UtcNow.Ticks);

                    long enabledTicks   = Interlocked.Read(ref _subscriptionEnabledTicksUtc);
                    long lastEventTicks = Interlocked.Read(ref _lastSecurityEventTicksUtc);
                    long probeEpoch     = Interlocked.Read(ref _securityProbeEpochTicks);
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
                    bool startupProbeCompleted = probeEpoch != DateTime.MinValue.Ticks
                        && (nowUtc.Ticks - probeEpoch) / (double)TimeSpan.TicksPerSecond
                           >= probeStartupWindowSeconds;
                    if (startupProbeCompleted && lastProbeEpochHandled != probeEpoch)
                    {
                        lastProbeEpochHandled = probeEpoch;

                        bool hasNoEventSinceEnable = lastEventTicks == DateTime.MinValue.Ticks ||
                                                     lastEventTicks <= probeEpoch;
                        if (hasNoEventSinceEnable)
                        {
                            // Tidak ada Security event sama sekali sejak subscription di-enable
                            SafeWriteEventLog("Application",
                                $"[HEALTH] Startup probe: no Security event in {probeStartupWindowSeconds}s since " +
                                $"subscription enabled. Possible hibernate resume or log rotation at wake. " +
                                $"Force re-subscribe + mini-replay.",
                                EventLogEntryType.Warning, 1079);

                            _securitySubscriptionStatus = "SILENT";

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
                    if (lastProbeEpochHandled != probeEpoch)
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

                    _securitySubscriptionStatus = "SILENT";

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

                    // Reset counter setelah re-subscribe berhasil:
                    //   _lastSecurityEventTicksUtc   → mid-day cooldown dihitung ulang dari sini
                    //   _subscriptionEnabledTicksUtc → referensi enable untuk startup probe
                    //   _securityProbeEpochTicks     → reset epoch startup probe
                    long nowTicks = DateTime.UtcNow.Ticks;
                    Interlocked.Exchange(ref _lastSecurityEventTicksUtc,   nowTicks);
                    Interlocked.Exchange(ref _subscriptionEnabledTicksUtc, nowTicks);
                    Interlocked.Exchange(ref _securityProbeEpochTicks,     nowTicks);

                    _securitySubscriptionStatus = "RESUBSCRIBED";

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
            {
                SafeWriteEventLog("Application",
                    $"[HEALTH] All {maxAttempts} re-subscribe attempts failed for Security log. " +
                    "Will retry at next health check cycle (~30s). Consider checking EventLog permissions.",
                    EventLogEntryType.Error, 1085);
                _resubscribeFailed = true;
                _securitySubscriptionStatus = "FAILED";
                return;
            }

            _resubscribeFailed = false;

            // Mini-replay: tangkap event yang missed selama subscription mati.
            //
            // PENTING: Security log replay dan RawStore replay dijalankan dalam try-catch TERPISAH.
            // Alasan: EventLog.Entries adalah live collection — kalau log rotate selama iterasi,
            // akses index bisa throw ArgumentException/IndexOutOfRangeException (race condition).
            // Jika keduanya dalam satu try-catch, crash di Security replay akan skip RawStore
            // replay juga — padahal RawStore membaca dari disk lokal dan tidak tergantung pada
            // EventLog. Dengan memisahkan keduanya, RawStore replay tetap berjalan meski
            // Security log replay gagal.
            SafeWriteEventLog("Application",
                $"[HEALTH] Mini-replay: from={missedSinceUtc:O} to={replayToUtc:O}",
                EventLogEntryType.Information, 1082);

            bool securityReplayOk = false;

            // ── Step 1: Security log replay (sumber utama) ──────────────────────────
            // Jalankan di thread pool — ReplaySecurityEvents memanggil
            // ProcessSecurityEntryAsync secara sync (.GetAwaiter().GetResult())
            // sehingga perlu thread terpisah untuk hindari deadlock dari async context.
            try
            {
                await Task.Run(
                    () => _replayService.ReplaySecurityEvents(missedSinceUtc, replayToUtc),
                    cancellationToken);

                securityReplayOk = true;
            }
            catch (Exception ex)
            {
                // IndexOutOfRangeException / ArgumentException paling sering terjadi saat
                // Security log rotate tepat selama iterasi Entries[i]. Log dan lanjut ke
                // RawStore replay — jangan biarkan crash ini membatalkan keduanya.
                SafeWriteEventLog("Application",
                    $"[HEALTH] Mini-replay Security log error (proceeding to raw store): {ex.Message}",
                    EventLogEntryType.Warning, 1084);
            }

            // ── Step 2: RawStore replay (fallback / pelengkap) ──────────────────────
            // Selalu dijalankan — bukan hanya fallback ketika Security log crash.
            // Kalau Security log sudah di-rotate, RawStore menjadi sumber utama.
            // Kalau Security log berhasil, RawStore mengisi event yang mungkin tidak
            // tertangkap karena race condition write-then-rotate.
            try
            {
                await _replayService.ReplayFromRawStore(missedSinceUtc, replayToUtc);
            }
            catch (Exception ex)
            {
                SafeWriteEventLog("Application",
                    $"[HEALTH] Mini-replay raw store error: {ex.Message}",
                    EventLogEntryType.Warning, 1084);
            }

            SafeWriteEventLog("Application",
                $"[HEALTH] Mini-replay done: from={missedSinceUtc:O} to={replayToUtc:O} " +
                $"securityLogOk={securityReplayOk}",
                EventLogEntryType.Information, 1083);
        }

        /// <summary>
        /// Mendeteksi silent drop System log subscription dengan kombinasi waktu sunyi
        /// dan validasi record ID agar tidak false-positive saat log idle.
        /// </summary>
        private async Task SystemLogSubscriptionHealthCheckTask(CancellationToken cancellationToken)
        {
            const int silentThresholdSeconds = 7200; // 2 hours
            const int checkIntervalMinutes   = 10;
            const int maxResubscribeAttempts = 3;

            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    bool useFastRetry = _systemResubscribeFailed;
                    TimeSpan delay = useFastRetry
                        ? TimeSpan.FromSeconds(5)
                        : TimeSpan.FromMinutes(checkIntervalMinutes);
                    await Task.Delay(delay, cancellationToken);
                    if (useFastRetry)
                        _systemResubscribeFailed = false;

                    Interlocked.Exchange(ref _lastSystemHealthHeartbeatUtc, DateTime.UtcNow.Ticks);

                    if (systemEventLog == null)
                        continue;

                    DateTime nowUtc     = DateTime.UtcNow;
                    long lastEventTicks = Interlocked.Read(ref _lastSystemEventTicksUtc);
                    double silentSeconds = (nowUtc.Ticks - lastEventTicks) / (double)TimeSpan.TicksPerSecond;
                    if (silentSeconds < silentThresholdSeconds)
                        continue;

                    int lastObservedRecordId = Volatile.Read(ref _lastObservedSystemRecordId);

                    if (!TryGetSystemLogRecordWindow(lastObservedRecordId, out int latestRecordId, out DateTime? earliestMissedUtc))
                        continue;

                    if (latestRecordId < lastObservedRecordId)
                    {
                        Interlocked.Exchange(ref _lastObservedSystemRecordId, latestRecordId);
                        lastObservedRecordId = latestRecordId;
                    }

                    if (latestRecordId <= lastObservedRecordId)
                        continue;

                    DateTime missedSinceUtc = earliestMissedUtc
                        ?? (lastEventTicks <= DateTime.MinValue.Ticks
                            ? nowUtc.AddSeconds(-silentThresholdSeconds)
                            : new DateTime(lastEventTicks, DateTimeKind.Utc));

                    int silentMinutes = (int)(silentSeconds / 60);
                    SafeWriteEventLog("Application",
                        $"[HEALTH-SYS] System subscription silent {silentMinutes} min " +
                        $"(threshold={silentThresholdSeconds / 60} min) with recordId advance " +
                        $"lastObserved={lastObservedRecordId} latest={latestRecordId}. " +
                        $"Re-subscribe + mini-replay.",
                        EventLogEntryType.Warning, 1086);

                    bool resubscribed = await ResubscribeSystemLogAndMiniReplayAsync(
                        missedSinceUtc, nowUtc, maxResubscribeAttempts, cancellationToken);
                    if (resubscribed)
                        Interlocked.Exchange(ref _lastObservedSystemRecordId, latestRecordId);
                }
                catch (TaskCanceledException) { break; }
                catch (Exception ex)
                {
                    SafeWriteEventLog("Application",
                        $"[HEALTH-SYS] SystemLogSubscriptionHealthCheckTask fatal: {ex.Message}",
                        EventLogEntryType.Error, 1090);

                    try { await Task.Delay(TimeSpan.FromMinutes(1), cancellationToken); }
                    catch (TaskCanceledException) { break; }
                }
            }
        }

        /// <summary>
        /// Ambil record ID terbaru dan timestamp entry paling awal setelah lastObservedRecordId.
        /// Return false kalau log kosong atau tidak bisa dibaca.
        /// </summary>
        private bool TryGetSystemLogRecordWindow(
            int lastObservedRecordId,
            out int latestRecordId,
            out DateTime? earliestMissedUtc)
        {
            latestRecordId = 0;
            earliestMissedUtc = null;

            try
            {
                if (systemEventLog == null) return false;

                int count = systemEventLog.Entries.Count;
                if (count == 0) return false;

                // Akses [count - 1] bisa throw ArgumentException kalau log rotate
                // tepat setelah kita baca count. Tangkap dan return false — caller
                // akan retry di check cycle berikutnya.
                EventLogEntry latest;
                try
                {
                    latest = systemEventLog.Entries[count - 1];
                }
                catch (ArgumentException)
                {
                    return false;
                }
                latestRecordId = latest.Index;

                if (latestRecordId <= lastObservedRecordId || lastObservedRecordId <= 0)
                    return true;

                for (int i = count - 1; i >= 0; i--)
                {
                    EventLogEntry entry;
                    try
                    {
                        entry = systemEventLog.Entries[i];
                    }
                    catch (ArgumentException)
                    {
                        // Log rotate saat iterasi — entry sebelum index ini sudah tidak ada.
                        // Hentikan iterasi; earliestMissedUtc yang sudah dikumpulkan tetap valid.
                        break;
                    }
                    if (entry.Index <= lastObservedRecordId)
                        break;

                    earliestMissedUtc = entry.TimeGenerated.ToUniversalTime();
                }

                return true;
            }
            catch (Exception ex)
            {
                SafeWriteEventLog("Application",
                    $"[HEALTH-SYS] TryGetSystemLogRecordWindow error: {ex.Message}",
                    EventLogEntryType.Warning, 1090);
                return false;
            }
        }

        /// <summary>
        /// Re-subscribe System log dan jalankan mini-replay System events untuk window yang missed.
        /// Analog dengan ResubscribeAndMiniReplayAsync untuk Security log.
        /// </summary>
        private async Task<bool> ResubscribeSystemLogAndMiniReplayAsync(
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
                            EventLogEntryType.Warning, 1088);
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
                        EventLogEntryType.Information, 1087);

                    resubscribed = true;
                    break;
                }
                catch (Exception ex)
                {
                    SafeWriteEventLog("Application",
                        $"[HEALTH-SYS] Re-subscribe System log attempt {attempt}/{maxAttempts} failed: {ex.Message}",
                        EventLogEntryType.Warning, 1088);

                    if (attempt < maxAttempts)
                        await Task.Delay(TimeSpan.FromSeconds(5), cancellationToken);
                }
            }

            if (!resubscribed)
            {
                SafeWriteEventLog("Application",
                    $"[HEALTH-SYS] All {maxAttempts} re-subscribe attempts failed for System log. " +
                    "Will retry at next health check cycle (~10m). Consider checking EventLog permissions.",
                    EventLogEntryType.Error, 1090);
                _systemResubscribeFailed = true;
                return false;
            }

            _systemResubscribeFailed = false;

            // ── System log mini-replay ───────────────────────────────────────────────
            // Sama dengan Security log: dua try-catch terpisah agar error di System log
            // replay tidak membatalkan RawStore replay (jika ada).
            // ReplaySystemEvents memanggil ProcessSystemEntryAsync secara sync (.GetAwaiter().GetResult())
            // → jalankan di thread pool untuk hindari deadlock dari async context.
            SafeWriteEventLog("Application",
                $"[HEALTH-SYS] Mini-replay System: from={missedSinceUtc:O} to={replayToUtc:O}",
                EventLogEntryType.Information, 1089);

            bool systemReplayOk = false;

            try
            {
                await Task.Run(
                    () => _replayService.ReplaySystemEvents(missedSinceUtc, replayToUtc),
                    cancellationToken);

                systemReplayOk = true;
            }
            catch (Exception ex)
            {
                SafeWriteEventLog("Application",
                    $"[HEALTH-SYS] Mini-replay System log error: {ex.Message}",
                    EventLogEntryType.Warning, 1090);
            }

            SafeWriteEventLog("Application",
                $"[HEALTH-SYS] Mini-replay System done: from={missedSinceUtc:O} to={replayToUtc:O} " +
                $"systemLogOk={systemReplayOk}",
                EventLogEntryType.Information, 1089);

            return true;
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

            // 4634: fallback logout.
            //
            // Raw List SharePoint: 4634 user standard SELALU masuk (kecuali 4634 admin — sudah
            // di-drop di admin correlation gate sebelum sampai ke sini).
            //
            // Summary List SharePoint: 4634 masuk summary dan update ShutdownTime HANYA jika:
            //   - status bukan STALE_SESSION_CLOSE (4634 yang fire ≤30 detik setelah 4624 —
            //     bukan logout sesungguhnya; raw record tetap di-dispatch sebagai audit trail)
            //   - tidak ada 4647/1074/6006-confirmed di queue yang sama — dikendalikan oleh
            //     priority system di TryUpdateDailySummaryShutdownAsync (4634 = priority 3,
            //     di bawah 4647=6, 1074=5, 6006-confirmed=4).
            //
            // Ketika ada dua atau lebih 4634 di hari yang sama, keduanya masuk summary queue.
            // TryUpdateDailySummaryShutdownAsync memilih yang shutdownTime LEBIH BESAR
            // (same-priority → ambil yang lebih baru) → selalu 4634 terakhir yang menang.
            if (item.EventId == 4634)
            {
                if (item.Status == "STALE_SESSION_CLOSE")
                    return false;
                return true;
            }

            // FIX [BUG-2+3]: Event 42 (Sleep/Modern Standby) sebagai last-resort shutdown.
            // Hanya masuk summary kalau belum ada ShutdownTime sama sekali (IsLastResort42 flag).
            // Validasi wake (apakah 42 ini shutdown final) dilakukan di TryDispatchQueuedEventAsync.
            if (item.EventId == 42)
                return item.IsLastResort42;

            return false;
        }

        /// <summary>
        /// Priority untuk shutdown group — HARUS selalu sinkron dengan SharePointIntegration.GetShutdownPriority.
        /// Dipakai untuk menentukan event mana di group yang boleh dispatch summary saat timer expired.
        ///
        ///   4647 = 6  HIGHEST — explicit user logoff
        ///   1074 shutdown = 5
        ///   6006 confirmed = 4
        ///   4634 = 3  Fallback logout — di bawah 1074/6006-confirmed.
        ///             Ketika ada dua 4634, same-priority → yang terbaru menang.
        ///   6008/41 = 1
        ///   6006 unconfirmed = 0
        ///   42 = -1 (last resort)
        ///
        /// Perubahan dari versi sebelumnya:
        ///   - 4634: 5 → 3. Sebelumnya (5) lebih tinggi dari 1074 (4) dan 6006-confirmed (3),
        ///     sehingga 4634 bisa mengalahkan system shutdown events yang lebih reliable.
        ///   - 1074/6006 tidak berubah nilainya; yang berubah hanya posisi relatif 4634.
        ///   - 6008, 41, 42 ditambahkan eksplisit (sebelumnya fall-through ke return 0).
        /// </summary>
        private static int GetShutdownEventPriority(int eventId, string eventType)
        {
            if (eventId == 4647) return 6;
            if (eventId == 1074 && !eventType.Contains("restart", StringComparison.OrdinalIgnoreCase)
                                && !eventType.Contains("reboot", StringComparison.OrdinalIgnoreCase)) return 5;
            if (eventId == 6006)
                return eventType.Contains("unconfirmed", StringComparison.OrdinalIgnoreCase) ? 0 : 4;
            if (eventId == 4634) return 3;
            if (eventId == 6008) return 1;
            if (eventId == 41)   return 1;
            if (eventId == 42)   return -1;
            return 0;
        }

        private async Task<bool> TryDispatchQueuedEventAsync(QueuedAttendanceEvent item, CancellationToken cancellationToken)
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
                string? accessToken = await sharePoint.GetAccessTokenAsync(item.EventTime, item.EventId, cancellationToken);
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
                            // Priority (GetShutdownEventPriority): 4647=6, 1074=5, 6006-confirmed=4, 4634=3.
                            //
                            // 4647 (6) > 6006-confirmed (4) → 4647 menang, mark 6006 sebagai dispatched.
                            // 4634 (3) < 6006-confirmed (4) → 6006 yang dispatch, 4634 di-skip.
                            if (item.EventId == 4647)
                            {
                                // 4647 menang atas confirmed 6006 — mark 6006 sebagai summaryDispatched
                                // agar 6006 tidak kirim summary lagi setelahnya.
                                await eventQueue.MarkGroupSummaryDispatchedAsync(item.ShutdownGroupId, exceptQueueId: item.QueueId);
                                SafeWriteEventLog("Application",
                                    $"[DISPATCH] Shutdown group: 4647 (priority 6) wins over confirmed 6006 (priority 4). " +
                                    $"queueId={item.QueueId} groupId={item.ShutdownGroupId}",
                                    EventLogEntryType.Information, 4009);
                                // needsSummary tetap true — 4647 yang dispatch
                            }
                            else
                            {
                                // Bukan 4647 (termasuk 4634 priority 3) — confirmed 6006 (priority 4) menang.
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
                        item.EventId, item.EventType, item.ComputerName, cancellationToken);

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
                            item.LoginTime ?? item.EventTime, summaryCache, item.Status, cancellationToken);
                    }
                    else
                    {
                        SafeWriteEventLog("Application",
                            $"[DISPATCH] Sending summary shutdown: user={item.Username} computer={item.ComputerName} " +
                            $"shutdownTime={item.ShutdownTime?.ToString("O") ?? item.EventTime.ToString("O")} " +
                            $"eventId={item.EventId} eventType='{item.EventType}'",
                            EventLogEntryType.Information, 4005);

                        IReadOnlyDictionary<string, List<DateTime>> allLogonSnapshot = SnapshotAllLogon4624Index();

                        await sharePoint.TryUpdateDailySummaryShutdownAsync(
                            accessToken, item.Username, item.ComputerName,
                            item.ShutdownTime ?? item.EventTime,
                            item.EventId, item.EventType,
                            allLogonSnapshot,
                            summaryCache,
                            cancellationToken);
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
                Interlocked.Exchange(ref _lastCleanupHeartbeatUtc, DateTime.UtcNow.Ticks);
                try
                {
                    DateTime now = DateTime.Now;

                    // ── LOCAL CLEANUP (setiap hari, saat startup) ─────────────────
                    // Tidak perlu koordinasi — jalan segera kalau belum cleanup hari ini.
                    if (lastLocalCleanupDate.Date < now.Date)
                    {
                        try
                        {
                            await summaryCache.CleanupOldEntriesAsync(cancellationToken);
                            await allLogon4624IndexStore.CleanupOldEntriesAsync(DateTime.Today.AddDays(-7), cancellationToken);
                            await rawEventStore.CleanupOldDatesAsync(eventQueue, cancellationToken);
                            SafeWriteEventLog("Application",
                                $"[CLEANUP] Local cleanup done for {now.Date:yyyy-MM-dd}.",
                                EventLogEntryType.Information, 5006);
                        }
                        catch (Exception ex)
                        {
                            SafeWriteEventLog("Application",
                                $"[CLEANUP] Local cleanup error: {ex.Message} — will retry tomorrow.",
                                EventLogEntryType.Warning, 5008);
                        }
                        finally
                        {
                            lastLocalCleanupDate = now.Date;
                        }
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

        private async Task HeartbeatWriterTask(CancellationToken cancellationToken)
        {
            TimeSpan interval = TimeSpan.FromMinutes(30);

            while (!cancellationToken.IsCancellationRequested)
            {
                Interlocked.Exchange(ref _lastHeartbeatTaskHeartbeatUtc, DateTime.UtcNow.Ticks);

                try
                {
                    if (!string.IsNullOrWhiteSpace(_heartbeatListId))
                    {
                        DateTime nowUtc = DateTime.UtcNow;
                        int queueCount = await eventQueue.GetCountAsync(cancellationToken);

                        // LastEventTime: kapan terakhir 4624 / 4647 masuk queue
                        long lastEventTicks = Interlocked.Read(ref _lastEnqueuedLoginLogoutEventTicksUtc);
                        DateTime? lastEventTimeUtc = lastEventTicks == DateTime.MinValue.Ticks
                            ? (DateTime?)null
                            : new DateTime(lastEventTicks, DateTimeKind.Utc);

                        // LastSecurityEventTime: kapan terakhir event APAPUN dari Security log diterima.
                        // Kalau ini recent tapi LastEventTime stale → subscription hidup,
                        // hanya Windows tidak fire 4624 (Fast Startup / session resume).
                        long lastSecurityTicks = Interlocked.Read(ref _lastSecurityEventTicksUtc);
                        DateTime? lastSecurityEventTimeUtc = lastSecurityTicks == DateTime.MinValue.Ticks
                            ? (DateTime?)null
                            : new DateTime(lastSecurityTicks, DateTimeKind.Utc);

                        string securitySubscriptionStatus = _securitySubscriptionStatus;

                        string serviceVersion = typeof(LoginLogoutMonitorService).Assembly
                            .GetCustomAttribute<System.Reflection.AssemblyInformationalVersionAttribute>()
                            ?.InformationalVersion ?? "unknown";

                        string? accessToken = await sharePointIntegration.Value.GetAccessTokenAsync(nowUtc, 0, cancellationToken);
                        if (string.IsNullOrWhiteSpace(accessToken))
                        {
                            SafeWriteEventLogAlways("Application",
                                "[HEARTBEAT] Access token unavailable — heartbeat skipped.",
                                EventLogEntryType.Warning, 1098);
                        }
                        else
                        {
                            await sharePointIntegration.Value.UpsertHeartbeatAsync(
                                accessToken,
                                _heartbeatListId,
                                Environment.MachineName,
                                nowUtc,
                                queueCount,
                                lastEventTimeUtc,
                                lastSecurityEventTimeUtc,
                                securitySubscriptionStatus,
                                serviceVersion,
                                cancellationToken);
                            SafeWriteEventLog("Application",
                                $"[HEARTBEAT] OK: machine={Environment.MachineName} " +
                                $"queue={queueCount} lastEvent={lastEventTimeUtc?.ToString("O") ?? "(none)"} " +
                                $"lastSecurityEvent={lastSecurityEventTimeUtc?.ToString("O") ?? "(none)"} " +
                                $"securityStatus={securitySubscriptionStatus}",
                                EventLogEntryType.Information, 1098);
                        }
                    }
                }
                catch (TaskCanceledException) { break; }
                catch (Exception ex)
                {
                    SafeWriteEventLogAlways("Application",
                        $"[HEARTBEAT] Failed to write heartbeat: {ex.Message}",
                        EventLogEntryType.Warning, 1098);
                }

                try { await Task.Delay(interval, cancellationToken); }
                catch (TaskCanceledException) { break; }
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
        // _securityProbeEpochTicks: epoch untuk startup probe Security log (reset tiap re-subscribe).
        private long _lastSecurityEventTicksUtc   = DateTime.MinValue.Ticks;
        private long _subscriptionEnabledTicksUtc = DateTime.MinValue.Ticks;
        private long _securityProbeEpochTicks     = DateTime.MinValue.Ticks;
        private volatile bool _resubscribeFailed = false;

        // Status subscription Security log — ditulis ke heartbeat SharePoint.
        // Membedakan dua kondisi yang tampak sama dari LastEventTime saja:
        //   "subscription hidup, Windows tidak fire 4624 (Fast Startup)" vs
        //   "subscription benar-benar drop silently".
        // volatile: dibaca dari HeartbeatWriterTask tanpa lock.
        private volatile string _securitySubscriptionStatus = "OK";

        // ── System log subscription health check ────────────────────────────────
        // _lastSystemEventTicksUtc: kapan terakhir OnSystemEventWritten dipanggil.
        // _lastObservedSystemRecordId: record ID terakhir yang benar-benar diterima handler.
        // Dipakai untuk synthetic validation agar tidak false-positive saat log idle.
        private long _lastSystemEventTicksUtc          = DateTime.UtcNow.Ticks;
        private int _lastObservedSystemRecordId        = 0;
        private long _systemSubscriptionEnabledTicksUtc = DateTime.MinValue.Ticks;
        private volatile bool _systemResubscribeFailed = false;

        // ── Background task heartbeats ──────────────────────────────────────────
        private long _lastQueueProcessorHeartbeatUtc = DateTime.MinValue.Ticks;
        private long _lastCleanupHeartbeatUtc = DateTime.MinValue.Ticks;
        private long _lastSecurityHealthHeartbeatUtc = DateTime.MinValue.Ticks;
        private long _lastSystemHealthHeartbeatUtc = DateTime.MinValue.Ticks;
        private long _lastHeartbeatTaskHeartbeatUtc = DateTime.MinValue.Ticks;

        private long _lastEnqueuedLoginLogoutEventTicksUtc = DateTime.MinValue.Ticks;

        private void OnSecurityEventWritten(object sender, EntryWrittenEventArgs e)
        {
            if (e?.Entry == null) return;

            // Reset health check counter — subscription masih hidup.
            // Setiap Security event (apapun ID-nya) membuktikan subscription aktif.
            // _lastSecurityEventTicksUtc dipakai oleh SecurityLogSubscriptionHealthCheckTask
            // untuk membedakan "subscription drop" vs "Windows tidak fire 4624 (Fast Startup)".
            Interlocked.Exchange(ref _lastSecurityEventTicksUtc, DateTime.UtcNow.Ticks);
            _securitySubscriptionStatus = "OK";

            EventLogEntry entry = e.Entry;
            if (_replayService.ShouldSkipLiveEntry(entry.TimeGenerated.ToUniversalTime(), isSecurityEvent: true))
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
                    _checkpointService.SaveStopCheckpoint(DateTime.UtcNow.AddMinutes(-1));
                }
            });
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
                    // ── Startup warmup guard ──────────────────────────────────────────────
                    //
                    // Race condition yang dicegah:
                    //   (a) replayInProgress=true  → ReplayFromRawStore sedang berjalan,
                    //       _adminSessions belum selesai ter-hydrate dari disk.
                    //   (b) _adminCacheWarm=false   → replay sudah selesai, tapi grace delay
                    //       di DrainDeferred4634Async belum lewat — ada celah commit time.
                    //
                    // Di kedua kondisi tersebut, IsAdminSession() bisa memberi hasil salah:
                    //   - false-pass  → logout admin lolos ke SharePoint
                    //   - false-block → logout user biasa di-drop sebagai "admin"
                    //
                    // Solusi: defer ke _deferred4634Queue, bukan drop atau proses langsung.
                    // DrainDeferred4634Async() akan reprocess ulang setelah warmup selesai.
                    //
                    // Note: writeRawRecord=true path sudah selesai di atas (SaveRawSecurityEventAsync)
                    // sehingga event sudah aman di disk — defer tidak menyebabkan data loss.
                    bool isReplayRunning = _replayService.IsReplayInProgress;
                    bool isCacheNotWarm  = !_adminCacheWarm;

                    if (isReplayRunning || isCacheNotWarm)
                    {
                        // Jangan defer ulang event yang sudah dari drain path (writeRawRecord=false
                        // artinya ini adalah reprocessing dari deferred queue).
                        // Jika masih defer ini bisa loop — proses langsung sebagai fallback.
                        if (!writeRawRecord)
                        {
                            // Ini path drain-retry: warmup belum selesai tapi sudah retry.
                            // Lanjut proses dengan state terbaik yang tersedia — lebih baik
                            // dari infinite defer. Log agar bisa dianalisis.
                            SafeWriteEventLog("Application",
                                $"[4634-RETRY] Warmup masih berlangsung saat retry — " +
                                $"memproses dengan state terkini. " +
                                $"replayRunning={isReplayRunning} adminCacheWarm={_adminCacheWarm} " +
                                $"computer={computerName} eventTime={eventTime:O}",
                                EventLogEntryType.Warning, 2056);
                            // Lanjut ke processing normal di bawah — jangan return.
                        }
                        else
                        {
                            // Live path: defer ke queue, return segera.
                            EnqueueDeferred4634(log);
                            SafeWriteEventLog("Attendance-Service",
                                $"[4634-RETRY] Deferring unresolved logout during replay warmup. " +
                                $"replayRunning={isReplayRunning} adminCacheWarm={_adminCacheWarm} " +
                                $"computer={computerName} eventTime={eventTime:O}",
                                EventLogEntryType.Information, 2050);
                            return;
                        }
                    }
                    // ── End startup warmup guard ──────────────────────────────────────────

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
                                $"[4634-FILTER] Admin logout filtered after correlation. " +
                                $"logonId={logonId4634} user={username4634} computer={computerName} " +
                                $"time={eventTime:O} writeRawRecord={writeRawRecord}",
                                EventLogEntryType.Information, 2042);
                            return; // tidak di-enqueue, tidak di-dispatch, tidak ke SharePoint
                        }
                    }
                    // ── End admin correlation gate ────────────────────────────────────────

                    // Check: apakah 4647 untuk user+computer+workDate ini sudah ada di queue?
                    // Kalau ada, 4634 tidak diperlukan — skip.
                    string workDate4634 = eventTime.ToLocalTime().ToString("yyyy-MM-dd");

                    // Temporal dedup: deteksi 4634 yang fire dalam 30 detik setelah 4624 user yang sama.
                    // Ini adalah Windows behavior normal untuk logon type 11 (CachedInteractive /
                    // unlock screen) — Windows menutup sesi lama dan membuka sesi baru hampir
                    // bersamaan, menyebabkan 4634 (sesi lama ditutup) fire tepat setelah 4624 baru.
                    // 4634 seperti ini BUKAN logout user — tidak boleh update ShutdownTime di summary.
                    // Window 30 detik aman: logout sesungguhnya selalu punya gap >> 30 detik dari login.
                    //
                    // FIX: sebelumnya stale 4634 di-drop total (return tanpa dispatch).
                    // Sekarang tetap di-dispatch ke raw list SharePoint sebagai audit trail,
                    // tapi di-blok dari summary update via status="STALE_SESSION_CLOSE".
                    // ShouldProcessSummary akan return false untuk status ini.
                    // Is4634StaleAsync cek dua sumber: queue in-memory DAN RawEventStore disk.
                    const int staleSessionWindowSeconds = 30;
                    bool isStaleSessionClose = await Is4634StaleAsync(
                        username4634,
                        computerName,
                        workDate4634,
                        eventTime,
                        staleSessionWindowSeconds);
                    if (isStaleSessionClose)
                    {
                        SafeWriteEventLog("Attendance-Service",
                            $"[DBG-4634] Stale session close — raw-only dispatch, summary skipped: " +
                            $"4634 fired within {staleSessionWindowSeconds}s of 4624 login. " +
                            $"user='{username4634}' computer='{computerName}' time={eventTime:O}",
                            EventLogEntryType.Information, 2033);

                        // Raw-only: dispatch ke raw list tapi tidak update summary.
                        await ProcessEvent(
                            4634, username4634, eventTime, computerName,
                            "Security", 0, null, writeRawRecord,
                            usernameResolutionSource: "Direct",
                            isFallback: true,
                            fallbackSource: "Event4634_StaleSessionClose",
                            status: "STALE_SESSION_CLOSE");
                        return;
                    }

                    bool has4647 = await eventQueue.Has4647InQueueAsync(
                        username4634,
                        computerName,
                        workDate4634);
                    if (has4647)
                    {
                        SafeWriteEventLog("Attendance-Service",
                            $"[DBG-4634] Skipped — 4647 already queued for user='{username4634}' " +
                            $"computer='{computerName}' at {eventTime:O}",
                            EventLogEntryType.Information, 2033);
                        return;
                    }

                    SafeWriteEventLog("Attendance-Service",
                        $"[4634-RETRY] Session resolved successfully after warmup — " +
                        $"promoting as fallback logout: user='{username4634}' " +
                        $"computer='{computerName}' at {eventTime:O} " +
                        $"(writeRawRecord={writeRawRecord}, no 4647 in queue)",
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
                        string? linkedLogonId = SecurityEventParser.GetLinkedLogonId(adminExcerpt ?? eventMessage);
                        string linkedSuffix = string.IsNullOrEmpty(linkedLogonId)
                            ? string.Empty
                            : $" linkedLogonId={linkedLogonId}";

                        _adminCorrelationService.RegisterAdminSession(
                            computerName,
                            adminLogonId,
                            linkedLogonId,
                            $"[ADMIN] Admin session cached for correlation (live 4624): " +
                            $"logonId={adminLogonId}{linkedSuffix} computer={computerName}");
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

            EventLogEntry entry = e.Entry;

            // Reset System log health check counter — subscription masih hidup.
            // Dipakai oleh SystemLogSubscriptionHealthCheckTask untuk mendeteksi
            // subscription drop pasca log-rotate atau resume dari hibernate.
            Interlocked.Exchange(ref _lastSystemEventTicksUtc, DateTime.UtcNow.Ticks);
            Volatile.Write(ref _lastObservedSystemRecordId, entry.Index);

            if (_replayService.ShouldSkipLiveEntry(entry.TimeGenerated.ToUniversalTime()))
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
                    _checkpointService.SaveStopCheckpoint(DateTime.UtcNow.AddMinutes(-1));
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
                    if (eventId == 4624 || eventId == 4647)
                        Interlocked.Exchange(ref _lastEnqueuedLoginLogoutEventTicksUtc, eventTime.ToUniversalTime().Ticks);

                    await CheckQueueSizeThresholdAsync(cancellationToken: default);

                    // FIX [CRASH-0xe0434352]: Checkpoint per-event — tulis setiap kali event
                    // berhasil masuk queue. eventTime - 1 detik agar event ini ikut di-replay
                    // kalau service restart sebelum dispatch selesai.
                    //
                    // PENTING: checkpoint hanya maju (never move backward).
                    // Guard monotonic dilakukan di CheckpointService dengan in-memory
                    // _lastWrittenCheckpoint yang di-init dari file existing.
                    DateTime candidate = eventTime.AddSeconds(-1);
                    _checkpointService.SaveStopCheckpoint(candidate);
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
                string? linkedLogonId = isAdmin
                    ? SecurityEventParser.GetLinkedLogonId(parsed.Message ?? parsed.MessageExcerpt)
                    : null;

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
                    // Field existing — membawa identitas admin session ke disk
                    LogonId        = logonId,
                    IsAdminLogon   = isAdmin,
                    // FIX: Persist LinkedLogonId agar replay path bisa register kedua sisi
                    // split-token ke AdminSessionCorrelationService setelah service restart.
                    // Tanpa ini, 4634 yang membawa LogonId = LinkedLogonId dari 4624 admin
                    // lolos admin gate di replay karena in-memory cache hanya berisi LogonId
                    // utama. Null untuk non-admin dan untuk 4634/4647.
                    LinkedLogonId  = linkedLogonId
                };

                // SELALU simpan — termasuk admin session.
                // RawEventStore kini berfungsi ganda: replay storage DAN session-correlation cache.
                // Menyimpan admin event ke disk TIDAK berarti di-enqueue atau di-dispatch.
                //
                // Retry dua kali untuk transient disk error (file lock, I/O momentary failure).
                // Jika semua attempt gagal, log event ID 4025 dan lanjut — event tetap diproses
                // dan di-enqueue ke persistent queue sehingga dispatch ke SharePoint tetap berjalan
                // meski local raw store tidak berhasil ditulis.
                bool rawSaved = false;
                Exception? rawSaveLastEx = null;
                for (int rawAttempt = 1; rawAttempt <= 2 && !rawSaved; rawAttempt++)
                {
                    try
                    {
                        await rawEventStore.SaveAsync(raw);
                        rawSaved = true;
                    }
                    catch (Exception ex)
                    {
                        rawSaveLastEx = ex;
                        if (rawAttempt < 2)
                            await Task.Delay(150);
                    }
                }

                if (!rawSaved)
                {
                    SafeWriteEventLog("Application",
                        $"[RAW-STORE] Failed to persist local raw event after 2 attempts — " +
                        $"eventId={eventId} computer={entry.MachineName} time={raw.EventTimeUtc:O}: " +
                        $"{rawSaveLastEx?.Message}",
                        EventLogEntryType.Warning, 4025);
                    // Tidak return — event tetap lanjut ke queue dispatch.
                }

                // Populate in-memory admin cache agar 4634 yang tiba di proses yang sama
                // bisa dikorelasikan tanpa disk read. Disk copy menangani skenario cross-restart.
                if (isAdmin && !string.IsNullOrEmpty(logonId))
                {
                    string linkedSuffix = string.IsNullOrEmpty(linkedLogonId)
                        ? string.Empty
                        : $" linkedLogonId={linkedLogonId}";

                    _adminCorrelationService.RegisterAdminSession(
                        entry.MachineName,
                        logonId,
                        linkedLogonId,
                        $"[ADMIN] Admin session saved for correlation: " +
                        $"user={username} logonId={logonId}{linkedSuffix} computer={entry.MachineName}");
                }
            }
            catch (Exception ex)
            {
                // Log exception yang tidak tertangkap di blok retry di atas
                // (misal: parsing error sebelum rawEventStore.SaveAsync dipanggil).
                // Tidak di-rethrow agar tidak membatalkan event processing pipeline di caller.
                SafeWriteEventLog("Application",
                    $"[RAW-STORE] SaveRawSecurityEventAsync unexpected error — " +
                    $"computer={entry?.MachineName}: {ex.Message}",
                    EventLogEntryType.Warning, 4025);
            }
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

        /// <summary>
        /// Deteksi apakah 4634 adalah "stale session close" — yaitu 4634 yang fire dalam
        /// <paramref name="windowSeconds"/> setelah 4624 user yang sama di komputer yang sama.
        ///
        /// Ini terjadi pada logon type 11 (CachedInteractive / unlock screen): Windows menutup
        /// sesi lama dan membuka sesi baru hampir bersamaan sehingga 4634 fire tepat setelah 4624.
        /// 4634 seperti ini BUKAN logout — tidak boleh jadi ShutdownTime di summary.
        ///
        /// Dua sumber dicek berurutan:
        ///   1. PersistentEventQueue (in-memory) — untuk live events di sesi ini.
        ///   2. RawEventStore (disk) — fallback jika service restart di antara 4624 dan 4634
        ///      sehingga 4624 sudah tidak ada di queue tapi masih ada di raw store.
        ///
        /// Fail-safe: jika RawEventStore gagal dibaca, return false (tidak blok 4634 secara salah).
        /// </summary>
        private async Task<bool> Is4634StaleAsync(
            string username,
            string computerName,
            string workDate,
            DateTime eventTimeUtc,
            int windowSeconds = 30,
            CancellationToken cancellationToken = default)
        {
            // Cek 1: queue in-memory (fast path)
            bool inQueue = await eventQueue.Has4624Within30sAsync(
                username, computerName, workDate, eventTimeUtc, windowSeconds, cancellationToken);
            if (inQueue)
                return true;

            // Cek 2: RawEventStore di disk (fallback untuk post-restart scenario)
            try
            {
                DateTime localDate = eventTimeUtc.ToLocalTime().Date;
                var rawLogins = rawEventStore.GetEventsForDate(computerName, localDate, 4624);
                return rawLogins.Any(r =>
                    r.Username != null &&
                    r.Username.Equals(username, StringComparison.OrdinalIgnoreCase) &&
                    r.EventTimeUtc <= eventTimeUtc &&
                    (eventTimeUtc - r.EventTimeUtc).TotalSeconds <= windowSeconds);
            }
            catch (Exception ex)
            {
                // Fail-safe: jangan blok 4634 jika RawStore gagal.
                // Lebih baik stale 4634 lolos ke raw-only daripada legitimate logout di-drop.
                SafeWriteEventLog("Application",
                    $"[DBG-4634] Is4634StaleAsync: RawStore read failed — treating as non-stale. " +
                    $"user='{username}' computer='{computerName}' time={eventTimeUtc:O} error={ex.Message}",
                    EventLogEntryType.Warning, 2033);
                return false;
            }
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

                    bool sent = await TryDispatchQueuedEventAsync(next, cancellationToken);
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
                    EventLogEntry entry;
                    try
                    {
                        entry = secLog.Entries[i];
                    }
                    catch (ArgumentException)
                    {
                        break; // log rotated during scan
                    }

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
                    EventLogEntry entry;
                    try
                    {
                        entry = secLog.Entries[i];
                    }
                    catch (ArgumentException)
                    {
                        break; // log rotated during scan
                    }
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
            // FIX-SHUTDOWN-PRIORITY: pecah menjadi same-device dan cross-device check.
            bool hasBetterShutdownSameDevice = allItems.Any(x =>
                x.QueueId != item.QueueId &&
                x.Username.Equals(item.Username, StringComparison.OrdinalIgnoreCase) &&
                x.ComputerName.Equals(item.ComputerName, StringComparison.OrdinalIgnoreCase) &&
                x.EventTime.ToLocalTime().ToString("yyyy-MM-dd") == workDate &&
                (x.EventId == 1074 || x.EventId == 4647 || x.EventId == 4634 ||
                 (x.EventId == 6006 && !x.EventType.Contains("unconfirmed", StringComparison.OrdinalIgnoreCase))));
            // FIX-SHUTDOWN-PRIORITY: Juga cek event dari device lain yang terjadi hampir bersamaan (≤120 detik).
            // Skenario bug: DEVICE-A fire 4647 jam 16:47:42, DEVICE-B fire 42 jam 16:47:46 (4 detik kemudian).
            // Tanpa cross-device check ini, 42 dari DEVICE-B dipromosikan karena tidak menemukan 4647
            // di queue DEVICE-B — padahal 4647 dari DEVICE-A sudah ada untuk user yang sama.
            // Window 120 detik dipilih karena rangkaian 4647+42 di dua device biasanya terjadi dalam ≤60 detik.
            // Skenario intended (LAPTOP logout 13:00, PC sleep 16:00) tidak terpengaruh karena
            // selisih waktu jauh melebihi 120 detik.
            bool hasBetterShutdownCrossDevice = allItems.Any(x =>
                x.QueueId != item.QueueId &&
                x.Username.Equals(item.Username, StringComparison.OrdinalIgnoreCase) &&
                !x.ComputerName.Equals(item.ComputerName, StringComparison.OrdinalIgnoreCase) &&
                Math.Abs((x.EventTime - item.EventTime).TotalSeconds) <= 120 &&
                (x.EventId == 1074 || x.EventId == 4647 || x.EventId == 4634 ||
                 (x.EventId == 6006 && !x.EventType.Contains("unconfirmed", StringComparison.OrdinalIgnoreCase))));
            bool hasBetterShutdown = hasBetterShutdownSameDevice || hasBetterShutdownCrossDevice;

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
                        EventLogEntry entry;
                        try
                        {
                            entry = secLog.Entries[i];
                        }
                        catch (ArgumentException)
                        {
                            break; // log rotated during scan
                        }
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
                        EventLogEntry entry;
                        try
                        {
                            entry = sysLog.Entries[i];
                        }
                        catch (ArgumentException)
                        {
                            break; // log rotated during scan
                        }
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
            List<string>? removedKeys = null;

            lock (firstLogonLock)
            {
                // Track earliest login (existing behavior)
                if (!firstLogon4624ByDeviceWorkDate.TryGetValue(key, out var existing) ||
                    eventTime < existing.EventTime)
                {
                    firstLogon4624ByDeviceWorkDate[key] = (username, eventTime);
                }

                // Track semua login untuk isNewSession check di shutdown dispatch
                lock (_allLogon4624Lock)
                {
                    if (!allLogon4624ByDeviceWorkDate.TryGetValue(key, out var logins))
                    {
                        logins = new List<DateTime>();
                        allLogon4624ByDeviceWorkDate[key] = logins;
                    }
                    if (!logins.Contains(eventTime))
                        logins.Add(eventTime);
                }

                // Prune harian dengan retention 7 hari (selaras MaxReplayLookback).
                // Key format: "COMPUTER::yyyy-MM-dd" — parse date dari suffix.
                if (DateTime.Today > _lastDictPruneDate)
                {
                    _lastDictPruneDate = DateTime.Today;
                    string cutoffDate = DateTime.Today.AddDays(-7).ToString("yyyy-MM-dd");
                    var staleKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                    foreach (string k in firstLogon4624ByDeviceWorkDate.Keys)
                    {
                        int sep = k.LastIndexOf("::", StringComparison.Ordinal);
                        if (sep >= 0 &&
                            string.Compare(k.Substring(sep + 2), cutoffDate, StringComparison.Ordinal) < 0)
                            staleKeys.Add(k);
                    }

                    lock (_allLogon4624Lock)
                    {
                        foreach (string k in allLogon4624ByDeviceWorkDate.Keys)
                        {
                            int sep = k.LastIndexOf("::", StringComparison.Ordinal);
                            if (sep >= 0 &&
                                string.Compare(k.Substring(sep + 2), cutoffDate, StringComparison.Ordinal) < 0)
                                staleKeys.Add(k);
                        }
                    }

                    removedKeys = staleKeys.ToList();

                    foreach (var k in removedKeys)
                    {
                        firstLogon4624ByDeviceWorkDate.Remove(k);
                        startupAnchorByDeviceWorkDate.Remove(k);
                    }
                    lock (_allLogon4624Lock)
                    {
                        foreach (var k in removedKeys)
                            allLogon4624ByDeviceWorkDate.Remove(k);
                    }

                    if (removedKeys.Count > 0)
                    {
                        SafeWriteEventLog("Application",
                            $"[DICT-PRUNE] Pruned {removedKeys.Count} stale workDate entries.",
                            EventLogEntryType.Information, 5007);
                    }
                }
            }

            _ = PersistAllLogon4624IndexAsync(key, eventTime, removedKeys);
        }

        private async Task PersistAllLogon4624IndexAsync(
            string key,
            DateTime eventTimeUtc,
            IReadOnlyCollection<string>? keysToRemove = null)
        {
            try
            {
                await allLogon4624IndexStore.UpdateAsync(
                    key,
                    eventTimeUtc,
                    keysToRemove);
            }
            catch (Exception ex)
            {
                SafeWriteEventLog("Application",
                    $"[INDEX-4624] Failed to persist allLogon4624 index update: {ex.Message}",
                    EventLogEntryType.Warning, 1056);
            }
        }

        private async Task LoadPersistedAllLogon4624IndexAsync(CancellationToken cancellationToken)
        {
            try
            {
                Dictionary<string, List<DateTime>> persisted =
                    await allLogon4624IndexStore.LoadAsync(cancellationToken);

                int loadedKeys = 0;
                lock (firstLogonLock)
                {
                    lock (_allLogon4624Lock)
                    {
                        foreach (var kvp in persisted)
                        {
                            var deduped = new List<DateTime>();
                            foreach (var t in kvp.Value)
                            {
                                if (!deduped.Contains(t))
                                    deduped.Add(t);
                            }

                            deduped.Sort();
                            if (deduped.Count == 0)
                                continue;

                            allLogon4624ByDeviceWorkDate[kvp.Key] = deduped;
                            loadedKeys++;
                        }
                    }
                }

                int removed = await allLogon4624IndexStore.CleanupOldEntriesAsync(
                    DateTime.Today.AddDays(-7),
                    cancellationToken);

                if (removed > 0)
                {
                    lock (firstLogonLock)
                    {
                        string cutoffDate = DateTime.Today.AddDays(-7).ToString("yyyy-MM-dd");
                        var toRemove = new List<string>();
                        lock (_allLogon4624Lock)
                        {
                            foreach (var k in allLogon4624ByDeviceWorkDate.Keys)
                            {
                                int sep = k.LastIndexOf("::", StringComparison.Ordinal);
                                if (sep >= 0 && string.Compare(k.Substring(sep + 2), cutoffDate, StringComparison.Ordinal) < 0)
                                    toRemove.Add(k);
                            }

                            foreach (string k in toRemove)
                                allLogon4624ByDeviceWorkDate.Remove(k);
                        }
                    }
                }

                SafeWriteEventLog("Application",
                    $"[INDEX-4624] Loaded persisted allLogon4624 index: keys={loadedKeys}.",
                    EventLogEntryType.Information, 1058);
            }
            catch (Exception ex)
            {
                SafeWriteEventLog("Application",
                    $"[INDEX-4624] Failed to load persisted allLogon4624 index: {ex.Message}",
                    EventLogEntryType.Warning, 1055);
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

        private IReadOnlyDictionary<string, List<DateTime>> SnapshotAllLogon4624Index()
        {
            lock (_allLogon4624Lock)
            {
                var snapshot = new Dictionary<string, List<DateTime>>(StringComparer.OrdinalIgnoreCase);
                foreach (var kvp in allLogon4624ByDeviceWorkDate)
                    snapshot[kvp.Key] = new List<DateTime>(kvp.Value);
                return snapshot;
            }
        }

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
                        // Tanpa ini, UPN prefix (nama.panjang) dari Pattern 3 tidak di-TitleCase
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

        // ── Deferred 4634 retry pipeline ─────────────────────────────────────────

        /// <summary>
        /// Enqueue satu live 4634 EventLogEntry ke deferred retry queue.
        ///
        /// Dipanggil dari live ProcessSecurityEntryAsync saat warmup guard aktif.
        /// ConcurrentQueue: lock-free, aman dari thread-pool concurrent calls.
        /// Capacity check pakai Interlocked.Increment — jika melebihi batas, entry baru
        /// di-discard dengan warning (kondisi ini praktis tidak terjadi, <5 event per startup).
        /// </summary>
        private void EnqueueDeferred4634(EventLogEntry entry)
        {
            int newCount = Interlocked.Increment(ref _deferred4634Count);
            if (newCount > Deferred4634MaxCapacity)
            {
                // Rollback counter dan tolak entry.
                Interlocked.Decrement(ref _deferred4634Count);
                SafeWriteEventLog("Application",
                    $"[4634-RETRY] Deferred queue penuh (capacity={Deferred4634MaxCapacity}) — " +
                    $"entry di-discard: computer={entry.MachineName} time={entry.TimeGenerated:O}. " +
                    $"Startup warmup mungkin berlangsung terlalu lama.",
                    EventLogEntryType.Warning, 2051);
                return;
            }
            _deferred4634Queue.Enqueue(new Deferred4634Entry(entry, DateTime.UtcNow));
        }

        /// <summary>
        /// Drain dan reprocess semua 4634 yang di-defer selama startup warmup.
        ///
        /// Dipanggil sebagai fire-and-forget dari background startup thread
        /// setelah ReplayMissedEventsFromCheckpoint() selesai.
        ///
        /// Algoritma:
        ///   1. Tunggu grace delay (5 detik) — beri waktu ProcessRawSecurityEventAsync
        ///      dari replay path selesai commit ke _adminSessions dictionary.
        ///      Replay tandai replayInProgress=false di finally{}, tapi ada lag kecil
        ///      antara flag turun dan cache fully populated.
        ///   2. Set _adminCacheWarm = true — live 4634 berikutnya tidak masuk deferred queue.
        ///   3. Dequeue tiap entry, evaluasi expiry + retry limit, lalu reprocess
        ///      via ProcessSecurityEntryAsync (writeRawRecord=false, sudah di disk).
        ///      Entry yang melebihi batas usia atau retry count: fallback ke processing
        ///      langsung dengan state terkini (bukan di-drop).
        ///   4. Entry yang gagal dan belum habis retry: re-enqueue dengan RetryCount+1,
        ///      lalu tunggu kecil sebelum iterasi berikutnya.
        ///
        /// Thread-safety:
        ///   - ConcurrentQueue: lock-free dequeue.
        ///   - _adminCacheWarm volatile: set sebelum drain dimulai.
        ///   - _deferred4634Count Interlocked: dikurangi tiap dequeue.
        ///   - Tidak ada lock yang bisa deadlock dengan OnSecurityEventWritten.
        ///
        /// Tidak boleh throw ke caller — semua exception di-catch dan di-log.
        /// </summary>
        private async Task DrainDeferred4634Async(CancellationToken cancellationToken)
        {
            try
            {
                // Grace delay: pastikan admin cache hydration dari ReplayFromRawStore
                // sudah selesai sebelum kita re-evaluate admin gate.
                // 5 detik cukup bahkan untuk RawStore dengan ratusan file per hari.
                await Task.Delay(TimeSpan.FromSeconds(5), cancellationToken)
                          .ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Service stopping — set warm flag agar live path tidak ter-block selamanya.
                _adminCacheWarm = true;
                SafeWriteEventLog("Application",
                    "[4634-RETRY] DrainDeferred4634Async dibatalkan (service stopping) saat grace delay.",
                    EventLogEntryType.Warning, 2057);
                return;
            }

            // Dari titik ini, live 4634 masuk pipeline normal — bukan deferred queue.
            _adminCacheWarm = true;

            int queuedCount = _deferred4634Queue.Count;
            if (queuedCount == 0)
            {
                SafeWriteEventLog("Attendance-Service",
                    "[4634-RETRY] Drain: tidak ada deferred 4634 untuk di-reprocess. " +
                    "adminCacheWarm=true — live 4634 akan diproses langsung.",
                    EventLogEntryType.Information, 2052);
                return;
            }

            SafeWriteEventLog("Attendance-Service",
                $"[4634-RETRY] Drain dimulai: {queuedCount} deferred 4634 event(s) akan di-reprocess.",
                EventLogEntryType.Information, 2052);

            int processed  = 0;
            int filtered   = 0;
            int expired    = 0;
            int retried    = 0;

            // Snapshot count di awal drain — hanya proses sebanyak ini,
            // tidak ikut-ikutan entry yang di-re-enqueue selama drain berjalan.
            int maxToProcess = queuedCount;
            int iteration    = 0;

            while (iteration < maxToProcess &&
                   _deferred4634Queue.TryDequeue(out Deferred4634Entry? entry) &&
                   !cancellationToken.IsCancellationRequested)
            {
                Interlocked.Decrement(ref _deferred4634Count);
                iteration++;

                // ── Expiry check ─────────────────────────────────────────────────
                if (entry.IsExpired(Deferred4634MaxAge))
                {
                    SafeWriteEventLog("Application",
                        $"[4634-RETRY] Retry expired — processing dengan state terkini sebagai fallback. " +
                        $"computer={entry.Entry.MachineName} eventTime={entry.Entry.TimeGenerated:O} " +
                        $"arrivedUtc={entry.ArrivedUtc:O} retryCount={entry.RetryCount}",
                        EventLogEntryType.Warning, 2053);
                    expired++;
                    // Fallback: proses dengan state terkini, tidak di-drop.
                    goto processEntry;
                }

                // ── Retry limit check ────────────────────────────────────────────
                if (entry.IsRetryExhausted(Deferred4634MaxRetry))
                {
                    SafeWriteEventLog("Application",
                        $"[4634-RETRY] Retry limit ({Deferred4634MaxRetry}) tercapai — " +
                        $"processing dengan state terkini sebagai fallback. " +
                        $"computer={entry.Entry.MachineName} eventTime={entry.Entry.TimeGenerated:O}",
                        EventLogEntryType.Warning, 2053);
                    expired++;
                    goto processEntry;
                }

                processEntry:
                try
                {
                    SafeWriteEventLog("Attendance-Service",
                        $"[4634-RETRY] Reprocessing delayed logout. " +
                        $"computer={entry.Entry.MachineName} eventTime={entry.Entry.TimeGenerated:O} " +
                        $"retryCount={entry.RetryCount} arrivedUtc={entry.ArrivedUtc:O}",
                        EventLogEntryType.Information, 2054);

                    // Re-enter pipeline normal dengan full re-evaluation.
                    // writeRawRecord=false: event sudah tersimpan ke RawEventStore di pass pertama.
                    // _adminCacheWarm=true: warmup guard tidak akan memblok lagi.
                    // Admin gate, split-token check, session mapping — semua dijalankan ulang.
                    await ProcessSecurityEntryAsync(entry.Entry, writeRawRecord: false)
                          .ConfigureAwait(false);
                    processed++;

                    SafeWriteEventLog("Attendance-Service",
                        $"[4634-RETRY] Session resolved successfully after warmup — " +
                        $"computer={entry.Entry.MachineName} eventTime={entry.Entry.TimeGenerated:O}",
                        EventLogEntryType.Information, 2054);
                }
                catch (Exception ex)
                {
                    SafeWriteEventLog("Application",
                        $"[4634-RETRY] Error saat reprocessing: {ex.Message} — " +
                        $"computer={entry.Entry.MachineName} eventTime={entry.Entry.TimeGenerated:O}",
                        EventLogEntryType.Warning, 2055);

                    // Jika masih ada retry budget dan belum expired: re-enqueue.
                    if (!entry.IsRetryExhausted(Deferred4634MaxRetry) &&
                        !entry.IsExpired(Deferred4634MaxAge))
                    {
                        Deferred4634Entry retryEntry = entry.WithRetry();
                        int newCount = Interlocked.Increment(ref _deferred4634Count);
                        if (newCount <= Deferred4634MaxCapacity)
                        {
                            _deferred4634Queue.Enqueue(retryEntry);
                            retried++;
                            SafeWriteEventLog("Application",
                                $"[4634-RETRY] Re-enqueued untuk retry #{retryEntry.RetryCount}. " +
                                $"computer={entry.Entry.MachineName} eventTime={entry.Entry.TimeGenerated:O}",
                                EventLogEntryType.Information, 2054);
                        }
                        else
                        {
                            Interlocked.Decrement(ref _deferred4634Count);
                        }

                        // Delay kecil sebelum lanjut agar tidak spin tight.
                        try { await Task.Delay(TimeSpan.FromSeconds(3), cancellationToken).ConfigureAwait(false); }
                        catch (OperationCanceledException) { break; }
                    }
                }
            }

            SafeWriteEventLog("Attendance-Service",
                $"[4634-RETRY] Drain selesai: processed={processed} filtered(admin)={filtered} " +
                $"expired/fallback={expired} re-enqueued={retried}. " +
                $"adminCacheWarm=true — sistem berjalan penuh.",
                EventLogEntryType.Information, 2052);
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