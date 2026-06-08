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
            // FIX BUG-F: replayInProgress HARUS di-set true sebelum _replayUpperBoundTicks di-update.
            // Urutan sebelumnya (bound dulu, lalu flag) membuka race window di mana ShouldSkipLiveEntry
            // melihat bound baru tapi replayInProgress=false → live event di-skip dengan log ID 1038
            // ("older than replayUpperBound") padahal seharusnya 1037 ("during replay overlap").
            // Dengan urutan yang benar: bound belum bergerak saat flag masih false, sehingga tidak ada
            // live event yang ter-skip dengan alasan yang salah.
            replayInProgress = true;
            Interlocked.Exchange(ref _replayUpperBoundTicks, replayTo.Ticks);

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

                    // ── Phase 1: Security log replay (sumber primer) ─────────────────────────
                    // Security events harus selesai lebih dulu agar lastActiveUser ter-populate
                    // sebelum System events (1074/6006) diproses.
                    try
                    {
                        ReplaySecurityEvents(replayFrom, replayTo);
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
                    try
                    {
                        await ReplayFromRawStore(replayFrom.Value, replayTo);
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

            for (int i = _securityEventLog.Entries.Count - 1; i >= 0; i--)
            {
                // FIX BUG-A: Seluruh blok akses per-entry dibungkus try-catch.
                // EventLog.Entries adalah live collection — log rotation saat iterasi berlangsung
                // bisa menyebabkan Entries[i] throw ArgumentException (index tidak lagi valid)
                // atau TimeGenerated/InstanceId throw InvalidOperationException (entry partial/corrupt).
                // Sebelumnya: satu exception di index manapun mengabort seluruh loop — semua
                // entry di index lebih rendah (lebih lama) tidak pernah dikumpulkan, tanpa warning.
                // Setelah fix: entry bermasalah di-skip (log + continue), loop tetap berjalan.
                // ArgumentException → break (log sudah di-rotate, lanjutkan ke tahap berikutnya).
                // Exception lain     → continue (entry korup, lanjut ke entry berikutnya).
                EventLogEntry? entry = null;
                try
                {
                    entry = _securityEventLog.Entries[i];
                    DateTime eventTime = entry.TimeGenerated.ToUniversalTime();

                    if (eventTime < fromTime.Value)
                        continue;

                    if (eventTime > toTime)
                        continue;

                    int eventId = _getNormalizedEventId(entry);
                    if (eventId != 4624 && eventId != 4647 && eventId != 4634)
                        continue;

                    // Pre-filter 4624: skip irrelevant logon types saja.
                    // Admin split-token filtering TIDAK dilakukan di sini — deferral ke
                    // ProcessSecurityEntryAsync agar SaveRawSecurityEventAsync sempat
                    // menyimpan metadata Logon ID yang dibutuhkan untuk korelasi 4634.
                    if (eventId == 4624 && entry.Message != null)
                    {
                        int lt = SecurityEventParser.ParseLogonType(entry.Message);
                        if (!_isRelevantLogonType(lt))
                            continue;
                    }

                    entries.Add((eventTime, entry, eventId));
                }
                catch (ArgumentException)
                {
                    // Log sudah di-rotate selama iterasi: Entries[i] tidak lagi valid.
                    // Semua index lebih rendah juga tidak valid — hentikan loop dengan aman.
                    collectionErrors++;
                    _writeEventLog("Application",
                        $"[SEC-REPLAY] Security log rotated at index {i} during collection — stopping scan. " +
                        $"Collected {entries.Count} entries before rotation. RawStore replay will cover gap.",
                        EventLogEntryType.Warning, 1039);
                    break;
                }
                catch (Exception ex)
                {
                    // Entry di index ini korup atau tidak terbaca — skip dan lanjut.
                    collectionErrors++;
                    _writeEventLog("Application",
                        $"[SEC-REPLAY] Skipping corrupt Security entry at index {i}: {ex.GetType().Name}: {ex.Message}",
                        EventLogEntryType.Warning, 1039);
                    continue;
                }
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

            for (int i = _systemEventLog.Entries.Count - 1; i >= 0; i--)
            {
                // FIX BUG-C: Pola guard yang sama dengan ReplaySecurityEvents (FIX BUG-A).
                // System log juga live collection — rotation selama iterasi throw ArgumentException.
                // Lebih kritis di sini: 1074 harus mendahului 6006. Jika loop abort setelah 6006
                // terkumpul tapi sebelum 1074, urutan sort tetap benar (sort by time), tapi
                // jika 1074 sama sekali tidak terkumpul karena abort awal, 6006 menjadi unresolved.
                // Dengan per-entry guard: entry korup di-skip, loop lanjut mencari 1074 yang valid.
                EventLogEntry? entry = null;
                try
                {
                    entry = _systemEventLog.Entries[i];
                    DateTime eventTime = entry.TimeGenerated.ToUniversalTime();

                    if (eventTime < fromTime.Value)  // fromTime non-null guaranteed by guard above
                        continue;

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
                    collectionErrors++;
                    _writeEventLog("Application",
                        $"[SYS-REPLAY] System log rotated at index {i} during collection — stopping scan. " +
                        $"Collected {entries.Count} entries before rotation.",
                        EventLogEntryType.Warning, 1040);
                    break;
                }
                catch (Exception ex)
                {
                    // Entry korup — skip dan lanjut.
                    collectionErrors++;
                    _writeEventLog("Application",
                        $"[SYS-REPLAY] Skipping corrupt System entry at index {i}: {ex.GetType().Name}: {ex.Message}",
                        EventLogEntryType.Warning, 1040);
                    continue;
                }
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