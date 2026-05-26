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

            for (int i = _securityEventLog.Entries.Count - 1; i >= 0; i--)
            {
                EventLogEntry entry = _securityEventLog.Entries[i];
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

            _writeEventLog("Application",
                $"ReplaySecurityEvents: found {entries.Count} security events between {fromTime:O} and {toTime:O}.",
                EventLogEntryType.Information, 1032);

            entries.Sort((a, b) => a.Time.CompareTo(b.Time));

            foreach (var (time, entry, eventId) in entries)
            {
                _writeEventLog("Application",
                    $"ReplaySecurityEvents: processing EventId={eventId} at {time:O}",
                    EventLogEntryType.Information, 1033);

                // SaveRawSecurityEventAsync dipanggil di dalam ProcessSecurityEntryAsync
                // via writeRawRecord=true path — tidak perlu panggil lagi secara eksplisit.
                // Sebelumnya ada dua panggilan terpisah (eksplisit Task.Run + writeRawRecord),
                // yang menyebabkan double-write ke RawEventStore. RawEventStore.SaveAsync
                // memang idempotent via File.Exists, tapi race condition masih bisa terjadi
                // di window antara File.Exists check dan File.Move final.
                // Solusi: satu panggilan saja, lewat ProcessSecurityEntryAsync.
                _processSecurityEntryAsync(entry, true).GetAwaiter().GetResult();
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
                    EventLogEntryType.Warning, 1036);
                return;
            }

            // Collect matching entries first, then sort ASCENDING (oldest first).
            // CRITICAL: 1074 must be processed before 6006 so TryResolve1074StateFor6006
            // can find the username set by StoreLast1074State().
            var entries = new List<(DateTime Time, EventLogEntry Entry, int EventId)>();

            for (int i = _systemEventLog.Entries.Count - 1; i >= 0; i--)
            {
                EventLogEntry entry = _systemEventLog.Entries[i];
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

            _writeEventLog("Application",
                $"ReplaySystemEvents: found {entries.Count} system events between {fromTime:O} and {toTime:O}.",
                EventLogEntryType.Information, 1030);

            // Sort oldest-first so 1074 is always processed before its paired 6006
            entries.Sort((a, b) => a.Time.CompareTo(b.Time));

            foreach (var (time, entry, eventId) in entries)
            {
                _writeEventLog("Application",
                    $"ReplaySystemEvents: processing EventId={eventId} at {time:O} Source={entry.Source}",
                    EventLogEntryType.Information, 1031);

                _processSystemEntryAsync(entry, true).GetAwaiter().GetResult();
            }
        }

        /// <summary>
        /// Opsi 3: Replay 4624/4647 yang tersimpan di RawEventStore untuk window replayFrom–replayTo.
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
                            await _processRawSecurityEventAsync(raw, true);
                            totalProcessed++;
                        }
                        catch (Exception ex)
                        {
                            _writeEventLog("Application",
                                $"[RAW-REPLAY] Error processing raw event id={raw.EventId} " +
                                $"computer={raw.ComputerName} time={raw.EventTimeUtc:O}: {ex.Message}",
                                EventLogEntryType.Warning, 1036);
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
                _writeEventLog("Application",
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