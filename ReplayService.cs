using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace EventLogOutEmployeeService
{
    public partial class LoginLogoutMonitorService
    {
        private sealed class ReplayService
        {
            private readonly LoginLogoutMonitorService _owner;
            private volatile bool _replayInProgress = false;
            private DateTime _replayUpperBound = DateTime.MinValue;
            private volatile int _skipLogSuppressedCount = 0;
            private long _lastSkipLogTimeTicks = DateTime.MinValue.Ticks;

            // FIX BUG-2: Grace period for Security log events (4624/4647) past replayUpperBound.
            // Rationale: 4647 (logout) and its paired 42 (sleep) fire within 2-3 seconds of each
            // other. The 4647 comes from Security log, 42 from System log. Without the grace period,
            // 4647 at the boundary is dropped while 42 passes → missing logout records.
            private static readonly TimeSpan LiveEventGracePeriod = TimeSpan.FromSeconds(10);

            public ReplayService(LoginLogoutMonitorService owner)
            {
                _owner = owner;
            }

            public async Task ReplayMissedEventsFromCheckpoint()
            {
                DateTime replayTo = DateTime.UtcNow;
                _replayUpperBound = replayTo;
                _replayInProgress = true;

                try
                {
                    DateTime? replayFrom = _owner.checkpointService.LoadStopCheckpoint();

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

                    _owner.checkpointService.SaveReplayCheckpoint(replayTo);
                }
                catch (Exception ex)
                {
                    SafeWriteEventLog("Application",
                        $"Error while replaying startup events: {ex.Message}",
                        EventLogEntryType.Warning, 1014);
                }
                finally
                {
                    _replayInProgress = false;
                }
            }

            public void ReplaySecurityEvents(DateTime? fromTime, DateTime toTime)
            {
                if (_owner.securityEventLog == null)
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

                for (int i = _owner.securityEventLog.Entries.Count - 1; i >= 0; i--)
                {
                    EventLogEntry entry = _owner.securityEventLog.Entries[i];
                    DateTime eventTime = entry.TimeGenerated.ToUniversalTime();

                    if (eventTime < fromTime.Value)
                        continue;

                    if (eventTime > toTime)
                        continue;

                    int eventId = _owner.GetNormalizedEventId(entry);
                    if (eventId != 4624 && eventId != 4647 && eventId != 4634)
                        continue;

                    // Pre-filter 4624: skip irrelevant logon types saja.
                    // Admin split-token filtering TIDAK dilakukan di sini — deferral ke
                    // ProcessSecurityEntryAsync agar SaveRawSecurityEventAsync sempat
                    // menyimpan metadata Logon ID yang dibutuhkan untuk korelasi 4634.
                    if (eventId == 4624 && entry.Message != null)
                    {
                        int lt = SecurityEventParser.ParseLogonType(entry.Message);
                        if (!_owner.IsRelevantLogonType(lt))
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
                    _owner.ProcessSecurityEntryAsync(entry, writeRawRecord: true).GetAwaiter().GetResult();
                }
            }

            public void ReplaySystemEvents(DateTime? fromTime, DateTime toTime)
            {
                if (_owner.systemEventLog == null)
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

                for (int i = _owner.systemEventLog.Entries.Count - 1; i >= 0; i--)
                {
                    EventLogEntry entry = _owner.systemEventLog.Entries[i];
                    DateTime eventTime = entry.TimeGenerated.ToUniversalTime();

                    if (eventTime < fromTime.Value)  // fromTime non-null guaranteed by guard above
                        continue;

                    if (eventTime > toTime)
                        continue;

                    int eventId = _owner.GetNormalizedEventId(entry);
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

                    _owner.ProcessSystemEntryAsync(entry, writeRawRecord: true).GetAwaiter().GetResult();
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
                        var events4624 = _owner.rawEventStore.GetEventsForDate(date, 4624);
                        var events4647 = _owner.rawEventStore.GetEventsForDate(date, 4647);

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
                    return await _owner.eventQueue.IsFullyDispatchedAsync(
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

                    if (eventId == 4624 && !_owner.IsRelevantLogonType(logonType))
                        return;

                    // Admin session detection — gabungkan IsAdminLogon (field baru) dengan
                    // IsAdminSplitTokenLogin dari MessageExcerpt (backward-compat file lama).
                    bool isAdminRaw = raw.IsAdminLogon ||
                                      (eventId == 4624 && _owner.IsAdminSplitTokenLogin(raw.MessageExcerpt));

                    if (eventId == 4624 && isAdminRaw)
                    {
                        // Re-hydrate in-memory cache dari disk agar 4634 live yang datang
                        // setelah replay bisa dikorelasikan tanpa disk read lagi.
                        if (!string.IsNullOrEmpty(raw.LogonId))
                        {
                            _owner._adminCorrelationService.RegisterAdminSession(
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
                        username = _owner.ResolveUsernameBySid(username, sid);

                    if (string.IsNullOrEmpty(username) || !_owner.IsValidUsername(username))
                    {
                        if (eventId == 4647)
                        {
                            await _owner.ProcessEvent(
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
                        lock (_owner.userLock)
                            _owner.lastActiveUser = username;
                        lock (_owner.knownLoginLock)
                            _owner.lastKnownLoginByComputer[computerName] = (username, eventTime);
                        _owner.RegisterFirst4624Logon(computerName, username, eventTime);
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
                            if (_owner._adminCorrelationService.IsAdminSession(computerName, logonId4634raw, eventTime, isReplay: true))
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
                        var allQueue4634raw = await _owner.eventQueue.GetAllAsync();

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

                        await _owner.ProcessEvent(
                            4634, username, eventTime, computerName,
                            "Security", 0, null, writeRawRecord,
                            usernameResolutionSource: "Direct",
                            isFallback: true,
                            fallbackSource: "Event4634_Fallback4647",
                            status: "CONFIRMED");
                        return;
                    }

                    await _owner.ProcessEvent(eventId, username, eventTime, computerName,
                        "Security", logonType, null, writeRawRecord);
                }
                catch (Exception ex)
                {
                    SafeWriteEventLog("Application",
                        $"Error in ProcessRawSecurityEventAsync: {ex.Message}",
                        EventLogEntryType.Warning, 1009);
                }
            }

            public bool ShouldSkipLiveEntry(DateTime eventTime, bool isSecurityEvent = false)
            {
                // Security log events (4624/4647) get a grace period past replayUpperBound.
                DateTime effectiveBound = isSecurityEvent
                    ? _replayUpperBound.Add(LiveEventGracePeriod)
                    : _replayUpperBound;

                if (eventTime <= effectiveBound)
                {
                    if (_replayInProgress)
                    {
                        SafeWriteEventLog("Application",
                            $"Live event skipped during replay overlap: eventTime={eventTime:O} replayUpperBound={_replayUpperBound:O}",
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
                                $"Live event skipped — older than replayUpperBound: eventTime={eventTime:O} replayUpperBound={_replayUpperBound:O}{suffix}",
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
}
