using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace EventLogOutEmployeeService
{
    internal sealed class ReplayService
    {
        private readonly CheckpointService _checkpointService;
        private readonly PersistentEventQueue _eventQueue;
        private readonly RawEventStore _rawEventStore;
        private readonly EventLog? _securityEventLog;
        private readonly EventLog? _systemEventLog;
        private readonly Action<string, string, EventLogEntryType, int> _writeEventLog;
        private readonly Func<EventLogEntry, int> _getNormalizedEventId;
        private readonly Func<int, bool> _isRelevantLogonType;
        private readonly Func<EventLogEntry, bool, Task> _processSecurityEntryAsync;
        private readonly Func<EventLogEntry, bool, Task> _processSystemEntryAsync;
        private readonly Func<RawSecurityEvent, bool, Task> _processRawSecurityEventAsync;

        private volatile bool replayInProgress = false;
        private long _replayUpperBoundTicks = DateTime.MinValue.Ticks;

        /// <summary>
        /// True selama ReplayMissedEventsFromCheckpoint() berjalan.
        /// Dibaca oleh live 4634 warmup guard di LoginLogoutMonitorService
        /// untuk menentukan apakah event perlu di-defer ke retry queue.
        /// volatile — thread-safe tanpa lock.
        /// </summary>
        public bool IsReplayInProgress => replayInProgress;

        private volatile int _skipLogSuppressedCount = 0;
        // Ticks-based agar bisa diakses dengan Interlocked.Read (DateTime tidak thread-safe secara native)
        private long _lastSkipLogTimeTicks = DateTime.MinValue.Ticks;

        // FIX BUG-2: Grace period for Security log events (4624/4647) past replayUpperBound.
        // Rationale: 4647 (logout) and its paired 42 (sleep) fire within 2-3 seconds of each
        // other. The 4647 comes from Security log, 42 from System log. Without the grace period,
        // 4647 at the boundary is dropped while 42 passes → missing logout records.
        private static readonly TimeSpan LiveEventGracePeriod = TimeSpan.FromSeconds(10);

        public ReplayService(
            CheckpointService checkpointService,
            PersistentEventQueue eventQueue,
            RawEventStore rawEventStore,
            EventLog? securityEventLog,
            EventLog? systemEventLog,
            Action<string, string, EventLogEntryType, int> writeEventLog,
            Func<EventLogEntry, int> getNormalizedEventId,
            Func<int, bool> isRelevantLogonType,
            Func<EventLogEntry, bool, Task> processSecurityEntryAsync,
            Func<EventLogEntry, bool, Task> processSystemEntryAsync,
            Func<RawSecurityEvent, bool, Task> processRawSecurityEventAsync)
        {
            _checkpointService = checkpointService;
            _eventQueue = eventQueue;
            _rawEventStore = rawEventStore;
            _securityEventLog = securityEventLog;
            _systemEventLog = systemEventLog;
            _writeEventLog = writeEventLog;
            _getNormalizedEventId = getNormalizedEventId;
            _isRelevantLogonType = isRelevantLogonType;
            _processSecurityEntryAsync = processSecurityEntryAsync;
            _processSystemEntryAsync = processSystemEntryAsync;
            _processRawSecurityEventAsync = processRawSecurityEventAsync;
        }

        public async Task ReplayMissedEventsFromCheckpoint()
        {
            DateTime replayTo = DateTime.UtcNow;

            // Establish replay upper bound before enabling replay mode.
            // This avoids a window where replayInProgress=true but replayUpperBound
            // still contains DateTime.MinValue.
            Interlocked.Exchange(ref _replayUpperBoundTicks, replayTo.Ticks);
            replayInProgress = true;

            try
            {
                DateTime? replayFrom = _checkpointService.LoadStopCheckpoint();

                _writeEventLog("Application",
                    $"ReplayMissedEvents: replayFrom={replayFrom?.ToString("O") ?? "(none)"} replayTo={replayTo:O}",
                    EventLogEntryType.Information, 1034);

                if (replayFrom.HasValue)
                {
                    // FIX BUG-E: Setiap fase replay dibungkus try-catch TERPISAH.
                    // Sebelumnya satu outer try-catch melingkupi ketiga fase — jika Security replay
                    // throw exception yang lolos dari inner guard (mis. OutOfMemoryException atau
                    // exception lain yang bukan ArgumentException), outer catch menangkapnya dan
                    // ReplayFromRawStore + ReplaySystemEvents tidak pernah dijalankan.
                    // ResubscribeAndMiniReplayAsync sudah melakukan pemisahan ini; startup path harus
                    // mengikuti pola yang sama untuk konsistensi dan ketahanan yang setara.

                    // FIX [SEC-GAP]: ShouldSkipLiveEntry() memberi Security events (4624/4647)
                    // grace window +LiveEventGracePeriod (10s) di atas _replayUpperBoundTicks
                    // sebelum menganggap event itu "live, bukan tanggung jawab replay" (lihat
                    // ShouldSkipLiveEntry di bawah). Tapi upper-bound filter di ReplaySecurityEvents
                    // sendiri (`eventTime > toTime`) sebelumnya memakai replayTo yang SAMA tanpa
                    // extension yang setara — menciptakan dead zone: event Security yang jatuh di
                    // (replayTo, replayTo+grace] ditolak DUA-DUANYA — replay (dianggap "terlalu baru
                    // untuk window ini") dan live tap (dianggap "masih dalam grace window replay").
                    //
                    // Insiden nyata: 4624 pada replayTo+~7s saat startup replay hilang total dari
                    // Security-log-replay maupun RawStore-replay, tidak pernah sampai ke ProgramData
                    // raw store atau SharePoint — padahal event itu terkonfirmasi benar-benar terjadi
                    // (Windows Security log lokal + Sentinel forwarder, dua sumber independen).
                    //
                    // Fix: lebarkan upper bound scan Security log (dan RawStore, untuk konsistensi
                    // fallback) sebesar grace period yang sama, supaya cakupan replay dan live tap
                    // bersambungan, bukan cuma bersebelahan dengan celah di antaranya.
                    //
                    // System events TIDAK perlu perubahan ini: ShouldSkipLiveEntry tidak memberi
                    // grace period untuk event non-Security (lihat effectiveBound di bawah), jadi
                    // window replay System (replayTo) sudah align dengan window live-tap System
                    // (replayUpperBound tanpa grace) — tidak ada dead zone di jalur itu.
                    DateTime securityReplayTo = replayTo.Add(LiveEventGracePeriod);

                    _writeEventLog("Application",
                        $"[SEC-GAP] Security replay window widened by grace period: " +
                        $"scan upper bound={securityReplayTo:O} (replayTo={replayTo:O} + {LiveEventGracePeriod.TotalSeconds}s), " +
                        $"aligns with ShouldSkipLiveEntry's effectiveBound for Security events.",
                        EventLogEntryType.Information, 1043);

                    // ── Phase 1: Security log replay (sumber primer) ─────────────────────────
                    // Security events harus selesai lebih dulu agar lastActiveUser ter-populate
                    // sebelum System events (1074/6006) diproses.
                    try
                    {
                        ReplaySecurityEvents(replayFrom, securityReplayTo);
                    }
                    catch (Exception ex)
                    {
                        _writeEventLog("Application",
                            $"[STARTUP-REPLAY] Security log replay error (continuing to raw store): {ex.GetType().Name}: {ex.Message}",
                            EventLogEntryType.Warning, 1014);
                    }

                    // ── Phase 2: RawStore replay (fallback + pelengkap) ──────────────────────
                    // Selalu dijalankan — bukan hanya jika Phase 1 gagal.
                    // Menangkap 4624/4647 yang sudah hilang dari Security log karena rotation
                    // tapi sempat disimpan ke rawevents\ saat terjadi secara real-time.
                    //
                    // FIX [SEC-GAP]: window dilebarkan sama seperti Phase 1 (securityReplayTo).
                    // RawStore tidak digate oleh ShouldSkipLiveEntry, jadi ini bukan syarat untuk
                    // menutup dead zone di atas — tapi kalau tidak diselaraskan, Phase 1 dan Phase 2
                    // akan mengecek window yang berbeda untuk kelas event yang sama, yang membuat
                    // "RawStore replay will cover gap" (lihat pesan di ReplaySecurityEvents saat log
                    // rotation) tidak lagi benar untuk 10 detik terakhir window itu.
                    try
                    {
                        await ReplayFromRawStore(replayFrom.Value, securityReplayTo);
                    }
                    catch (Exception ex)
                    {
                        _writeEventLog("Application",
                            $"[STARTUP-REPLAY] RawStore replay error (continuing to system log): {ex.GetType().Name}: {ex.Message}",
                            EventLogEntryType.Warning, 1014);
                    }

                    // ── Phase 3: System log replay ───────────────────────────────────────────
                    // System events: extend replayFrom 30 detik lebih awal agar 1074 yang terjadi
                    // tepat sebelum checkpoint window tetap ter-load ke memory sebelum 6006 di-replay.
                    // Tanpa ini, 1074 di detik terakhir sebelum replayFrom ter-potong → 6006 unconfirmed.
                    // DedupWindow 30 detik akan tangkap duplikat kalau 1074 sudah ada di queue.
                    //
                    // Upper bound TETAP replayTo (bukan securityReplayTo) — lihat catatan FIX [SEC-GAP]
                    // di atas: System events tidak dapat grace period dari ShouldSkipLiveEntry, jadi
                    // melebarkan window di sini hanya akan menciptakan overlap yang tidak perlu dengan
                    // live tap, bukan menutup celah apa pun.
                    try
                    {
                        DateTime systemReplayFrom = replayFrom.Value.AddSeconds(-30);
                        ReplaySystemEvents(systemReplayFrom, replayTo);
                    }
                    catch (Exception ex)
                    {
                        _writeEventLog("Application",
                            $"[STARTUP-REPLAY] System log replay error: {ex.GetType().Name}: {ex.Message}",
                            EventLogEntryType.Warning, 1014);
                    }
                }
                else
                {
                    _writeEventLog("Application",
                        "ReplayMissedEvents: no checkpoint found, skipping replay.",
                        EventLogEntryType.Information, 1029);
                }

                // NOTE: checkpoint tetap disimpan sebagai replayTo (bukan securityReplayTo).
                // Konsekuensinya: startup berikutnya akan me-replay ulang window 10 detik terakhir
                // ini untuk Security events. Ini disengaja, bukan oversight — checkpoint yang
                // konservatif (mundur, bukan maju melewati apa yang pasti sudah tertangani live tap)
                // lebih aman, dan overlap-nya sudah ditangani oleh dedup di EnqueueIfNotDuplicateAsync.
                // Melebarkan checkpoint ke securityReplayTo akan menghemat sedikit re-scan tapi
                // menambah risiko: kalau grace period pernah diperbesar di kemudian hari, checkpoint
                // lama yang sudah "maju" duluan bisa membuat window itu tidak ke-cover di startup
                // berikutnya.
                _checkpointService.SaveReplayCheckpoint(replayTo);
            }
            catch (Exception ex)
            {
                _writeEventLog("Application",
                    $"Error while replaying startup events: {ex.Message}",
                    EventLogEntryType.Warning, 1014);
            }
            finally
            {
                replayInProgress = false;
            }
        }

        public void ReplaySecurityEvents(DateTime? fromTime, DateTime toTime)
        {
            if (_securityEventLog == null)
                return;

            // GUARD: fromTime null means no checkpoint exists — do NOT replay.
            // Without a lower bound we would re-import the entire Security log history.
            if (!fromTime.HasValue)
            {
                _writeEventLog("Application",
                    "ReplaySecurityEvents: fromTime is null — skipping to avoid full log flood.",
                    EventLogEntryType.Warning, 1035);
                return;
            }

            // Collect and sort ascending (oldest-first) for consistent ordering.
            var entries = new List<(DateTime Time, EventLogEntry Entry, int EventId)>();
            int collectionErrors = 0;

            // FIX-SPAM-1039: Track corrupt-skip count and first exception type separately
            // from collectionErrors (which also counts the rotation/ArgumentException case).
            // Per-entry logging of each corrupt entry caused thousands of 1039 events on
            // machines with large numbers of malformed Security log records. Replaced with
            // a single aggregated warning emitted once after the collection loop.
            int corruptSkipCount = 0;
            string? firstCorruptExType = null;

            // FIX OBS-1 (2026-07-21 incident, User D): aggregate count alone gave no way to
            // trace WHICH entry was lost. Capture index + event time (when readable) for each
            // skipped entry so a future incident can be correlated against Sentinel/raw store
            // directly instead of guessing from a bare count. Capped to avoid unbounded growth
            // on machines with many corrupt entries — same rationale as FIX-SPAM-1039.
            var corruptDetails = new List<string>();
            const int MaxCorruptDetailsLogged = 5;

            bool stopScanning = false;

            for (int i = _securityEventLog.Entries.Count - 1; i >= 0 && !stopScanning; i--)
            {
                // FIX BUG-A: Seluruh blok akses per-entry dibungkus try-catch.
                // EventLog.Entries adalah live collection — log rotation saat iterasi berlangsung
                // bisa menyebabkan Entries[i] throw ArgumentException (index tidak lagi valid)
                // atau TimeGenerated/InstanceId throw InvalidOperationException (entry partial/corrupt).
                // Sebelumnya: satu exception di index manapun mengabort seluruh loop — semua
                // entry di index lebih rendah (lebih lama) tidak pernah dikumpulkan, tanpa warning.
                // Setelah fix: entry bermasalah di-skip (log + continue), loop tetap berjalan.
                // ArgumentException → stop (log sudah di-rotate, lanjutkan ke tahap berikutnya).
                // Exception lain     → retry sekali, lalu skip kalau masih gagal (lihat RETRY-1).
                //
                // FIX PERF-1 (2026-07-21 incident, User D): iterasi berjalan descending
                // (terbaru → terlama), jadi begitu eventTime < fromTime.Value, SEMUA entry di
                // index lebih rendah juga pasti lebih lama — aman untuk stop total, bukan cuma
                // continue. Sebelumnya loop selalu memindai seluruh log (23k+ entries diamati di
                // produksi) pada setiap startup replay, apa pun umur checkpoint-nya. Scan
                // berkepanjangan ini memperlebar jendela race antara replay startup dan live
                // event tap (lihat ShouldSkipLiveEntry): makin lama replay berjalan, makin besar
                // kemungkinan event live tiba saat replayInProgress masih true dan ditolak oleh
                // jendela yang sudah lewat.
                //
                // FIX RETRY-1: exception non-rotation biasanya race transient melawan penulisan
                // log yang sedang berlangsung (lihat komentar FIX BUG-A) — bukan entry yang benar-
                // benar rusak permanen. Retry sekali setelah jeda singkat sebelum menyerah.
                EventLogEntry? entry = null;
                DateTime? readTime = null;
                Exception? lastEx = null;
                bool handled = false;

                for (int attempt = 0; attempt < 2 && !handled; attempt++)
                {
                    try
                    {
                        entry = _securityEventLog.Entries[i];
                        DateTime eventTime = entry.TimeGenerated.ToUniversalTime();
                        readTime = eventTime;

                        if (eventTime < fromTime.Value)
                        {
                            _writeEventLog("Application",
                                $"[SEC-REPLAY] Reached checkpoint lower bound at index {i} " +
                                $"(eventTime={eventTime:O} < fromTime={fromTime.Value:O}) — stopping scan, " +
                                "remaining entries are older.",
                                EventLogEntryType.Information, 1045);
                            stopScanning = true;
                            handled = true;
                            break;
                        }

                        if (eventTime <= toTime)
                        {
                            int eventId = _getNormalizedEventId(entry);
                            if (eventId == 4624 || eventId == 4647 || eventId == 4634)
                            {
                                // Pre-filter 4624: skip irrelevant logon types saja.
                                // Admin split-token filtering TIDAK dilakukan di sini — deferral ke
                                // ProcessSecurityEntryAsync agar SaveRawSecurityEventAsync sempat
                                // menyimpan metadata Logon ID yang dibutuhkan untuk korelasi 4634.
                                bool relevant = true;
                                if (eventId == 4624 && entry.Message != null)
                                {
                                    int lt = SecurityEventParser.ParseLogonType(entry.Message);
                                    relevant = _isRelevantLogonType(lt);
                                }

                                if (relevant)
                                    entries.Add((eventTime, entry, eventId));
                            }
                        }

                        handled = true;
                    }
                    catch (ArgumentException)
                    {
                        // Log sudah di-rotate selama iterasi: Entries[i] tidak lagi valid.
                        // Semua index lebih rendah juga tidak valid — hentikan loop dengan aman.
                        // Rotation sudah log satu event saja — tidak ada spam di sini.
                        collectionErrors++;
                        _writeEventLog("Application",
                            $"[SEC-REPLAY] Security log rotated at index {i} during collection — stopping scan. " +
                            $"Collected {entries.Count} entries before rotation. RawStore replay will cover gap.",
                            EventLogEntryType.Warning, 1039);
                        stopScanning = true;
                        handled = true;
                    }
                    catch (Exception ex)
                    {
                        lastEx = ex;
                        if (attempt == 0)
                        {
                            // FIX RETRY-1: beri jeda singkat lalu coba index yang sama sekali lagi —
                            // kebanyakan kasus ini adalah race sesaat melawan penulisan log live,
                            // yang biasanya selesai dalam puluhan milidetik.
                            Thread.Sleep(50);
                            continue;
                        }

                        // Kedua percobaan gagal — genuinely corrupt/inaccessible, menyerah untuk index ini.
                        collectionErrors++;
                        corruptSkipCount++;
                        if (firstCorruptExType == null)
                            firstCorruptExType = ex.GetType().Name;
                        if (corruptDetails.Count < MaxCorruptDetailsLogged)
                        {
                            corruptDetails.Add(readTime.HasValue
                                ? $"index={i},time={readTime.Value:O}"
                                : $"index={i},time=unknown");
                        }
                        handled = true;
                    }
                }
            }

            // FIX-SPAM-1039 / FIX OBS-1: satu aggregated warning menggantikan ribuan per-entry
            // logs, tapi sekarang menyertakan index+waktu (dibatasi MaxCorruptDetailsLogged) agar
            // bisa dikorelasikan ke sumber independen (Sentinel/Event Viewer) saat investigasi.
            // Tetap pakai event ID 1039 agar filter Event Viewer yang sudah ada tetap bekerja.
            if (corruptSkipCount > 0)
            {
                string detailSuffix = corruptDetails.Count > 0
                    ? $" [{string.Join("; ", corruptDetails)}" +
                      (corruptSkipCount > corruptDetails.Count ? $"; +{corruptSkipCount - corruptDetails.Count} more]" : "]")
                    : string.Empty;

                _writeEventLog("Application",
                    $"[SEC-REPLAY] Skipped {corruptSkipCount} corrupt Security entr{(corruptSkipCount == 1 ? "y" : "ies")} during collection " +
                    $"(exType={firstCorruptExType ?? "unknown"}){detailSuffix}.",
                    EventLogEntryType.Warning, 1039);
            }

            _writeEventLog("Application",
                $"ReplaySecurityEvents: found {entries.Count} security events between {fromTime:O} and {toTime:O}" +
                (collectionErrors > 0 ? $" ({collectionErrors} entries skipped due to rotation/corruption)" : "") + ".",
                EventLogEntryType.Information, 1032);

            entries.Sort((a, b) => a.Time.CompareTo(b.Time));

            int processErrors = 0;
            foreach (var (time, entry, eventId) in entries)
            {
                _writeEventLog("Application",
                    $"ReplaySecurityEvents: processing EventId={eventId} at {time:O}",
                    EventLogEntryType.Information, 1033);

                // FIX BUG-B: Per-entry try-catch di processing foreach.
                // Sebelumnya: satu exception dari _processSecurityEntryAsync mengabort seluruh loop —
                // semua entry valid sesudahnya tidak diproses. Contoh skenario gagal: entry ke-3
                // dari 10 throw NullReferenceException dari parsing message korup → entry 4-10 hilang.
                // Setelah fix: entry bermasalah di-skip dengan warning, loop tetap berjalan.
                // SaveRawSecurityEventAsync dipanggil di dalam ProcessSecurityEntryAsync
                // via writeRawRecord=true path — tidak perlu panggil lagi secara eksplisit.
                try
                {
                    _processSecurityEntryAsync(entry, true).GetAwaiter().GetResult();
                }
                catch (Exception ex)
                {
                    processErrors++;
                    _writeEventLog("Application",
                        $"[SEC-REPLAY] Error processing EventId={eventId} at {time:O} — skipping entry: " +
                        $"{ex.GetType().Name}: {ex.Message}",
                        EventLogEntryType.Warning, 1039);
                }
            }

            if (processErrors > 0)
            {
                _writeEventLog("Application",
                    $"[SEC-REPLAY] Completed with {processErrors}/{entries.Count} processing errors. " +
                    "RawStore replay will attempt recovery for failed entries.",
                    EventLogEntryType.Warning, 1039);
            }
        }

        public void ReplaySystemEvents(DateTime? fromTime, DateTime toTime)
        {
            if (_systemEventLog == null)
                return;

            // GUARD: fromTime null means no checkpoint — skip to avoid full log flood.
            if (!fromTime.HasValue)
            {
                _writeEventLog("Application",
                    "ReplaySystemEvents: fromTime is null — skipping to avoid full log flood.",
                    EventLogEntryType.Warning, 1040);
                return;
            }

            // Collect matching entries first, then sort ASCENDING (oldest first).
            // CRITICAL: 1074 must be processed before 6006 so TryResolve1074StateFor6006
            // can find the username set by StoreLast1074State().
            var entries = new List<(DateTime Time, EventLogEntry Entry, int EventId)>();
            int collectionErrors = 0;

            // FIX-SPAM-1040: Track corrupt-skip count and first exception type separately
            // from collectionErrors (which also counts the rotation/ArgumentException case).
            // Per-entry logging of each corrupt entry caused thousands of 1040 events on
            // machines with large numbers of malformed System log records. Replaced with
            // a single aggregated warning emitted once after the collection loop.
            int corruptSkipCount = 0;
            string? firstCorruptExType = null;

            bool stopScanning = false;

            for (int i = _systemEventLog.Entries.Count - 1; i >= 0 && !stopScanning; i--)
            {
                // FIX BUG-C: Pola guard yang sama dengan ReplaySecurityEvents (FIX BUG-A).
                // System log juga live collection — rotation selama iterasi throw ArgumentException.
                // Lebih kritis di sini: 1074 harus mendahului 6006. Jika loop abort setelah 6006
                // terkumpul tapi sebelum 1074, urutan sort tetap benar (sort by time), tapi
                // jika 1074 sama sekali tidak terkumpul karena abort awal, 6006 menjadi unresolved.
                // Dengan per-entry guard: entry korup di-skip, loop lanjut mencari 1074 yang valid.
                //
                // FIX PERF-1 (sama seperti ReplaySecurityEvents): descending iteration berarti
                // begitu eventTime < fromTime.Value, seluruh entry di index lebih rendah juga
                // lebih lama — stop total, bukan cuma continue, supaya startup replay tidak
                // memindai seluruh log setiap kali.
                EventLogEntry? entry = null;
                try
                {
                    entry = _systemEventLog.Entries[i];
                    DateTime eventTime = entry.TimeGenerated.ToUniversalTime();

                    if (eventTime < fromTime.Value)  // fromTime non-null guaranteed by guard above
                    {
                        stopScanning = true;
                        continue;
                    }

                    if (eventTime > toTime)
                        continue;

                    int eventId = _getNormalizedEventId(entry);
                    if (eventId != 1074 && eventId != 6006 && eventId != 6008 && eventId != 41 && eventId != 42)
                        continue;

                    entries.Add((eventTime, entry, eventId));
                }
                catch (ArgumentException)
                {
                    // Log sudah di-rotate selama iterasi — hentikan loop dengan aman.
                    // Rotation sudah log satu event saja (break) — tidak ada spam di sini.
                    collectionErrors++;
                    _writeEventLog("Application",
                        $"[SYS-REPLAY] System log rotated at index {i} during collection — stopping scan. " +
                        $"Collected {entries.Count} entries before rotation.",
                        EventLogEntryType.Warning, 1040);
                    break;
                }
                catch (Exception ex)
                {
                    // FIX-SPAM-1040: Entry korup — increment counter dan lanjut.
                    // JANGAN panggil _writeEventLog di sini: pada mesin dengan ribuan
                    // corrupt entries, per-entry log menghasilkan ribuan event 1040 yang
                    // membuat Event Viewer tidak bisa dipakai untuk troubleshooting.
                    // Summary warning satu baris ditulis setelah loop selesai.
                    collectionErrors++;
                    corruptSkipCount++;
                    if (firstCorruptExType == null)
                        firstCorruptExType = ex.GetType().Name;
                    continue;
                }
            }

            // FIX-SPAM-1040: Emit satu aggregated warning menggantikan ribuan per-entry logs.
            // Tetap pakai event ID 1040 agar filter Event Viewer yang sudah ada tetap bekerja.
            if (corruptSkipCount > 0)
            {
                _writeEventLog("Application",
                    $"[SYS-REPLAY] Skipped {corruptSkipCount} corrupt System entr{(corruptSkipCount == 1 ? "y" : "ies")} during collection " +
                    $"(exType={firstCorruptExType ?? "unknown"}).",
                    EventLogEntryType.Warning, 1040);
            }

            _writeEventLog("Application",
                $"ReplaySystemEvents: found {entries.Count} system events between {fromTime:O} and {toTime:O}" +
                (collectionErrors > 0 ? $" ({collectionErrors} entries skipped due to rotation/corruption)" : "") + ".",
                EventLogEntryType.Information, 1030);

            // Sort oldest-first so 1074 is always processed before its paired 6006
            entries.Sort((a, b) => a.Time.CompareTo(b.Time));

            int processErrors = 0;
            foreach (var (time, entry, eventId) in entries)
            {
                _writeEventLog("Application",
                    $"ReplaySystemEvents: processing EventId={eventId} at {time:O} Source={entry.Source}",
                    EventLogEntryType.Information, 1031);

                // FIX BUG-D: Per-entry try-catch di processing foreach.
                // Kritis untuk System events: 1074 dan 6006 harus keduanya diproses.
                // Sebelumnya: jika 6006 throw exception (misal NullRef), loop abort dan
                // 1074 sesudahnya (dalam urutan sort) tidak diproses → state mismatch permanen.
                // Catatan: sort sudah menjamin 1074 sebelum 6006 (by time), jadi bahaya utama
                // adalah 1074 berhasil tapi 6006 gagal, bukan sebaliknya.
                // Setelah fix: entry bermasalah di-skip, loop lanjut ke entry berikutnya.
                try
                {
                    _processSystemEntryAsync(entry, true).GetAwaiter().GetResult();
                }
                catch (Exception ex)
                {
                    processErrors++;
                    _writeEventLog("Application",
                        $"[SYS-REPLAY] Error processing EventId={eventId} at {time:O} — skipping entry: " +
                        $"{ex.GetType().Name}: {ex.Message}",
                        EventLogEntryType.Warning, 1040);
                }
            }

            if (processErrors > 0)
            {
                _writeEventLog("Application",
                    $"[SYS-REPLAY] Completed with {processErrors}/{entries.Count} processing errors.",
                    EventLogEntryType.Warning, 1040);
            }
        }

        /// <summary>
        /// Opsi 3: Replay 4624/4647/4634 yang tersimpan di RawEventStore untuk window replayFrom–replayTo.
        /// Ini fallback kalau Security log sudah ter-rotate/clear sebelum ReplaySecurityEvents bisa baca.
        /// DedupWindow di EnqueueIfNotDuplicateAsync akan otomatis skip event yang sudah ada di queue.
        /// </summary>
        public async Task ReplayFromRawStore(DateTime replayFrom, DateTime replayTo)
        {
            try
            {
                DateTime localFrom = replayFrom.ToLocalTime().Date;
                DateTime localTo   = replayTo.ToLocalTime().Date;
                int totalProcessed = 0;

                for (DateTime date = localFrom; date <= localTo; date = date.AddDays(1))
                {
                    // Struktur flat: rawevents\{yyyyMMdd}\ — tidak ada subfolder per PC
                    var events4624 = _rawEventStore.GetEventsForDate(Environment.MachineName, date, 4624);
                    var events4647 = _rawEventStore.GetEventsForDate(Environment.MachineName, date, 4647);
                    var events4634 = _rawEventStore.GetEventsForDate(Environment.MachineName, date, 4634);

                    var allEvents = events4624.Concat(events4647).Concat(events4634)
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
                            await _processRawSecurityEventAsync(raw, true);
                            totalProcessed++;
                        }
                        catch (Exception ex)
                        {
                            // FIX BUG-G: Gunakan event ID 1041 untuk per-item error agar bisa
                            // dibedakan dari success (1036) dan outer catch (1042) di Event Viewer.
                            // Sebelumnya ketiganya pakai 1036 — filter tidak bisa membedakan
                            // mana warning dan mana informational.
                            _writeEventLog("Application",
                                $"[RAW-REPLAY] Error processing raw event id={raw.EventId} " +
                                $"computer={raw.ComputerName} time={raw.EventTimeUtc:O}: {ex.Message}",
                                EventLogEntryType.Warning, 1041);
                        }
                    }
                }

                if (totalProcessed > 0)
                {
                    _writeEventLog("Application",
                        $"[RAW-REPLAY] Replayed {totalProcessed} raw security events from RawEventStore " +
                        $"({replayFrom:O} – {replayTo:O})",
                        EventLogEntryType.Information, 1036);
                }
            }
            catch (Exception ex)
            {
                // FIX BUG-G: Event ID 1042 untuk outer error — terpisah dari per-item error (1041)
                // dan success (1036). Memudahkan triaging: 1042 berarti seluruh ReplayFromRawStore
                // gagal (mis. GetEventsForDate throw), bukan sekadar satu event yang gagal diproses.
                _writeEventLog("Application",
                    $"[RAW-REPLAY] Error in ReplayFromRawStore: {ex.Message}",
                    EventLogEntryType.Warning, 1042);
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
                return await _eventQueue.IsFullyDispatchedAsync(
                    raw.EventId, raw.ComputerName, raw.EventTimeUtc);
            }
            catch
            {
                return false;
            }
        }

        public bool ShouldSkipLiveEntry(DateTime eventTime, bool isSecurityEvent = false)
        {
            DateTime replayUpperBound = new DateTime(
                Interlocked.Read(ref _replayUpperBoundTicks),
                DateTimeKind.Utc);

            // Security log events (4624/4647) get a grace period past replayUpperBound.
            DateTime effectiveBound = isSecurityEvent
                ? replayUpperBound.Add(LiveEventGracePeriod)
                : replayUpperBound;

            if (eventTime <= effectiveBound)
            {
                if (replayInProgress)
                {
                    _writeEventLog("Application",
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
                        _writeEventLog("Application",
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
    }
}