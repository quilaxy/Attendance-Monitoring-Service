using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace EventLogOutEmployeeService
{
    // ── Opsi 3: Raw Event Store ───────────────────────────────────────────────────
    // Menyimpan raw event (4624/4647/6005) ke disk segera saat EntryWritten fire,
    // SEBELUM diproses ke queue. Tujuan: kalau Security log di-rotate/clear sebelum
    // service sempat replay, data tetap ada di sini dan bisa di-ingest ulang.
    //
    // Format file: rawevents\{yyyyMMdd}\{eventId}_{ticks}.json
    // Retention: 7 hari (dibersihkan bersamaan cleanup SharePoint).
    // ─────────────────────────────────────────────────────────────────────────────

    public class RawSecurityEvent
    {
        public int    EventId      { get; set; }
        public string ComputerName { get; set; } = string.Empty;
        public DateTime EventTimeUtc { get; set; }
        public int    LogonType    { get; set; }
        public string? Username    { get; set; }
        public string? Sid         { get; set; }
        /// <summary>Subset message yang dibutuhkan untuk re-process: section "New Logon:" atau "Subject:"</summary>
        public string? MessageExcerpt { get; set; }
        public string  Source       { get; set; } = "Security";

        /// <summary>
        /// Logon ID (hex string, misal "0x9dc2c3a") dari section "New Logon:" (4624)
        /// atau "Subject:" (4634/4647). Dipakai untuk cross-reference 4634 → 4624:
        /// kalau 4624 dengan Logon ID yang sama sudah difilter sebagai admin,
        /// 4634-nya juga harus di-skip.
        /// </summary>
        public string? LogonId { get; set; }

        /// <summary>
        /// True kalau event 4624 ini difilter oleh IsAdminSplitTokenLogin.
        /// Disimpan ke disk agar path replay bisa tahu bahwa Logon ID ini milik admin
        /// tanpa perlu re-parse full message yang sudah tidak ada.
        /// Selalu false untuk 4634 dan 4647.
        /// </summary>
        public bool IsAdminLogon { get; set; } = false;

        /// <summary>
        /// Linked Logon ID (hex string, misal "0xdef456") dari event 4624 admin split-token.
        ///
        /// Windows UAC split-token menghasilkan DUA event 4624 saat admin login:
        ///   - Elevated token  : LogonId=0xABC, LinkedLogonId=0xDEF
        ///   - Standard token  : LogonId=0xDEF, LinkedLogonId=0xABC
        ///
        /// Keduanya menghasilkan 4634 saat session ditutup — masing-masing 4634 membawa
        /// LogonId dari sesinya sendiri. Agar kedua 4634 terblokir di admin gate (termasuk
        /// setelah service restart via replay path), kita harus register KEDUANYA ke
        /// AdminSessionCorrelationService:
        ///   - LogonId utama  → di-register via field LogonId (sudah ada sebelumnya)
        ///   - LinkedLogonId  → di-register via field ini (FIX baru)
        ///
        /// Null untuk non-admin (IsAdminLogon = false), untuk 4634, dan untuk 4647.
        /// Null juga kalau LinkedLogonId dari message adalah 0x0 (tidak ada linked session).
        /// </summary>
        public string? LinkedLogonId { get; set; }
    }

    public class RawEventStore
    {
        private readonly string baseDirectory;
        // Retention 7 hari — selaras dengan MaxReplayLookback di LoginLogoutMonitorService.
        // Alasan dinaikkan dari 2 hari:
        //   - Security log 20MB bisa rotate dalam hitungan jam di environment high-traffic.
        //   - Service bisa mati tanpa sc failure (Windows Update, 6008 power loss, dsb)
        //     sehingga gap bisa lebih dari 2 hari sebelum ada yang sadar dan restart manual.
        //   - Tanpa RawEventStore, replay hanya bisa recover dari Security log yang sudah rotate.
        //   - 7 hari cover weekend panjang + libur nasional tanpa ada yang perlu intervensi.
        // Data yang disimpan: Username (Windows), SID, ComputerName, EventTime, LogonType.
        // Tidak ada email, password, atau data personal lain — aman untuk retensi 7 hari.
        // Estimasi ukuran: ~1KB/event × ~200 event/hari × 7 hari ≈ 1.4MB total, sangat kecil.
        private static readonly TimeSpan RetentionWindow = TimeSpan.FromDays(7);

        // Hard cap: folder lebih dari HardCapWindow SELALU dihapus tanpa cek dispatch status.
        // Mencegah folder menumpuk kalau SharePoint down berhari-hari dan cleanup normal terus di-skip.
        // 14 hari = 2× RetentionWindow — cukup panjang agar tidak agresif, cukup pendek agar
        // tidak ada akumulasi data yang tidak perlu.
        private static readonly TimeSpan HardCapWindow = TimeSpan.FromDays(14);
        // #10: writeLock global dihilangkan.
        // File path sudah unik per event: {eventId}_{ticks}.json
        // File.Move (temp→final) atomic di Windows untuk same-volume.
        // Concurrent saves ke file path yang berbeda tidak butuh serialisasi.
        // Idempotency dijaga oleh File.Exists check sebelum write.

        public RawEventStore(string baseDirectory)
        {
            this.baseDirectory = baseDirectory;
            Directory.CreateDirectory(baseDirectory);
        }

        /// <summary>
        /// Simpan raw event ke disk secara fire-and-forget. Tidak throw.
        /// Dipanggil dari OnSecurityEventWritten SEBELUM ProcessEntry.
        /// </summary>
        public async Task SaveAsync(RawSecurityEvent evt)
        {
            try
            {
                string dir = Path.Combine(
                    baseDirectory,
                    evt.EventTimeUtc.ToLocalTime().ToString("yyyyMMdd"));
                Directory.CreateDirectory(dir);

                // Nama file unik: eventId + ticks — concurrent writes ke file berbeda aman
                string fileName = $"{evt.EventId}_{evt.EventTimeUtc.Ticks}.json";
                string filePath = Path.Combine(dir, fileName);

                // Idempotent — kalau sudah ada (replay), skip tanpa lock
                if (File.Exists(filePath))
                    return;

                string content = JsonConvert.SerializeObject(evt, Formatting.Indented);
                string tempPath = filePath + ".tmp";
                await File.WriteAllTextAsync(tempPath, content);
                // File.Move atomic di Windows (same-volume). overwrite: false agar idempotent
                // kalau dua thread race ke file yang sama — salah satu akan throw IOException,
                // yang di-swallow oleh catch di bawah. Data tidak corrupt.
                File.Move(tempPath, filePath, overwrite: false);
            }
            catch { /* fire-and-forget */ }
        }

        /// <summary>
        /// Fix 1: Expose path builder agar ReplayFromRawStore tidak perlu hardcode ProgramData.
        /// </summary>
        public string GetDateDirectory(DateTime localDate)
            => Path.Combine(baseDirectory, localDate.ToString("yyyyMMdd"));

        /// <summary>
        /// Ambil semua raw event untuk workDate tertentu, sorted ascending.
        /// Dipakai sebagai fallback kalau Security log lokal sudah ter-rotate.
        /// Struktur folder flat: rawevents\{yyyyMMdd}\ — tidak ada subfolder per PC
        /// karena service hanya jalan di satu PC dan ComputerName selalu sama.
        /// </summary>
        public List<RawSecurityEvent> GetEventsForDate(DateTime localDate, int eventId)
        {
            var result = new List<RawSecurityEvent>();
            try
            {
                string dir = Path.Combine(baseDirectory, localDate.ToString("yyyyMMdd"));
                if (!Directory.Exists(dir))
                    return result;

                string prefix = $"{eventId}_";
                foreach (string file in Directory.GetFiles(dir, $"{prefix}*.json", SearchOption.TopDirectoryOnly))
                {
                    try
                    {
                        string content = File.ReadAllText(file);
                        var evt = JsonConvert.DeserializeObject<RawSecurityEvent>(content);
                        if (evt != null)
                            result.Add(evt);
                    }
                    catch { /* skip corrupt file */ }
                }

                result.Sort((a, b) => a.EventTimeUtc.CompareTo(b.EventTimeUtc));
            }
            catch { /* silent fail */ }
            return result;
        }

        /// <summary>
        /// Overload dengan computerName untuk backward-compat panggilan dari
        /// GetRawEventsFromStore dan ResolveFirst4624 — filter post-read by ComputerName.
        /// </summary>
        public List<RawSecurityEvent> GetEventsForDate(string computerName, DateTime localDate, int eventId)
            => GetEventsForDate(localDate, eventId)
                .Where(e => e.ComputerName.Equals(computerName, StringComparison.OrdinalIgnoreCase))
                .ToList();

        /// <summary>
        /// Cleanup folder lebih dari RetentionWindow (7 hari), dengan hard cap 14 hari.
        /// Sebelum menghapus, verifikasi semua file di folder sudah dispatched ke SharePoint
        /// via eventQueue.IsFullyDispatchedAsync. Kalau ada yang belum, folder di-skip
        /// dan dicoba lagi di cleanup berikutnya.
        /// </summary>
        public async Task CleanupOldDatesAsync(PersistentEventQueue eventQueue, CancellationToken cancellationToken = default)
        {
            try
            {
                DateTime softCutoff = DateTime.Today.Subtract(RetentionWindow);  // 7 hari
                DateTime hardCutoff = DateTime.Today.Subtract(HardCapWindow);    // 14 hari

                foreach (string dateDir in Directory.GetDirectories(baseDirectory))
                {
                    string dirName = Path.GetFileName(dateDir);
                    if (!DateTime.TryParseExact(dirName, "yyyyMMdd",
                        System.Globalization.CultureInfo.InvariantCulture,
                        System.Globalization.DateTimeStyles.None, out DateTime dirDate))
                        continue;

                    // Belum melewati soft cutoff (7 hari) — skip sama sekali
                    if (dirDate.Date >= softCutoff.Date)
                        continue;

                    // Lewat hard cap (14 hari) — hapus tanpa cek dispatch status.
                    // Safety valve: kalau SharePoint down berhari-hari dan dispatch terus gagal,
                    // folder tidak akan menumpuk selamanya.
                    if (dirDate.Date < hardCutoff.Date)
                    {
                        try
                        {
                            Directory.Delete(dateDir, recursive: true);
                            SafeRawLog(
                                $"[RawEventStore] Hard cap cleanup — deleted {dirName} (>{HardCapWindow.Days} days old, forced).",
                                EventLogEntryType.Warning, 5012);
                        }
                        catch { /* skip if locked */ }
                        continue;
                    }

                    // Antara 7–14 hari: cek dispatch status dulu sebelum hapus (perilaku normal).
                    bool allDispatched = await AllEventsDispatchedAsync(dateDir, eventQueue, cancellationToken);
                    if (!allDispatched)
                    {
                        SafeRawLog(
                            $"[RawEventStore] Cleanup SKIP {dirName} — ada event yang belum dispatched ke SharePoint.",
                            EventLogEntryType.Warning, 5010);
                        continue;
                    }

                    try
                    {
                        Directory.Delete(dateDir, recursive: true);
                        SafeRawLog(
                            $"[RawEventStore] Cleanup OK — deleted {dirName} (all events dispatched).",
                            EventLogEntryType.Information, 5011);
                    }
                    catch { /* skip if locked */ }
                }
            }
            catch { /* silent fail */ }
        }

        /// <summary>
        /// Cek apakah semua file JSON di folder sudah fully dispatched di queue.
        /// Event yang tidak ada di queue (sudah dihapus dari queue setelah dispatch) dianggap selesai.
        /// Event yang ada di queue tapi belum dispatched → return false.
        /// </summary>
        private static async Task<bool> AllEventsDispatchedAsync(
            string dateDir, PersistentEventQueue eventQueue, CancellationToken cancellationToken)
        {
            try
            {
                var rawEvents = new List<(int EventId, string ComputerName, DateTime EventTimeUtc)>();
                foreach (string file in Directory.GetFiles(dateDir, "*.json", SearchOption.TopDirectoryOnly))
                {
                    try
                    {
                        string content = File.ReadAllText(file);
                        var evt = Newtonsoft.Json.JsonConvert.DeserializeObject<RawSecurityEvent>(content);
                        if (evt != null)
                            rawEvents.Add((evt.EventId, evt.ComputerName, evt.EventTimeUtc));
                    }
                    catch { /* skip corrupt file */ }
                }

                if (rawEvents.Count == 0)
                    return true;

                return await eventQueue.AllEventsDispatchedBulkAsync(rawEvents, cancellationToken);
            }
            catch { return true; } // kalau tidak bisa baca folder, anggap aman untuk dihapus
        }

        private static void SafeRawLog(string message, EventLogEntryType type, int eventId)
        {
            // 5011 = normal "deleted, all dispatched" — verbose only
            // 5010 = "skipped, not all dispatched" — always show (indicates pending data)
            // 5012 = hard cap deletion — always show (indicates persistent SP issue)
            if (!LoginLogoutMonitorService.VerboseLogging && eventId == 5011)
                return;
            try { EventLog.WriteEntry("Attendance-Service", message, type, eventId); }
            catch { }
        }

    }

    /// <summary>
    /// Persistensi lokal untuk allLogon4624ByDeviceWorkDate (key: "COMPUTER::yyyy-MM-dd").
    /// Menjaga daftar timestamp login 4624 agar isNewSession tetap akurat setelah restart.
    /// </summary>
    public class PersistentLogonIndex
    {
        private readonly string filePath;
        private readonly SemaphoreSlim fileLock = new SemaphoreSlim(1, 1);
        private Dictionary<string, List<DateTime>> _cache =
            new Dictionary<string, List<DateTime>>(StringComparer.OrdinalIgnoreCase);
        private bool _cacheInitialized = false;

        public PersistentLogonIndex(string filePath)
        {
            this.filePath = filePath;
            EnsureFile();
        }

        public async Task<Dictionary<string, List<DateTime>>> LoadAsync(CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                await EnsureCacheAsync();
                return CloneCache();
            }
            finally
            {
                fileLock.Release();
            }
        }

        public async Task UpdateAsync(
            string key,
            DateTime eventTimeUtc,
            IReadOnlyCollection<string>? keysToRemove = null,
            CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                await EnsureCacheAsync();
                bool changed = false;

                if (keysToRemove != null)
                {
                    foreach (string removeKey in keysToRemove)
                        changed |= _cache.Remove(removeKey);
                }

                if (!_cache.TryGetValue(key, out var logins))
                {
                    logins = new List<DateTime>();
                    _cache[key] = logins;
                    changed = true;
                }

                if (!logins.Contains(eventTimeUtc))
                {
                    logins.Add(eventTimeUtc);
                    changed = true;
                }

                if (changed)
                    await WriteAllInternalAsync(_cache);
            }
            finally
            {
                fileLock.Release();
            }
        }

        public async Task<int> CleanupOldEntriesAsync(DateTime cutoffDateLocal, CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                await EnsureCacheAsync();
                int removed = 0;
                var toRemove = new List<string>();

                foreach (var key in _cache.Keys)
                {
                    if (TryParseWorkDate(key, out DateTime workDate) && workDate.Date < cutoffDateLocal.Date)
                        toRemove.Add(key);
                }

                foreach (string key in toRemove)
                {
                    if (_cache.Remove(key))
                        removed++;
                }

                if (removed > 0)
                    await WriteAllInternalAsync(_cache);

                return removed;
            }
            finally
            {
                fileLock.Release();
            }
        }

        // ── Internal helpers ─────────────────────────────────────────────────────

        private void EnsureFile()
        {
            string? dir = Path.GetDirectoryName(filePath);
            if (!string.IsNullOrWhiteSpace(dir) && !Directory.Exists(dir))
                Directory.CreateDirectory(dir);

            if (!File.Exists(filePath))
                File.WriteAllText(filePath, JsonConvert.SerializeObject(new LogonIndexData()));
        }

        private async Task EnsureCacheAsync()
        {
            if (_cacheInitialized) return;
            _cache = await ReadAllInternalAsync();
            _cacheInitialized = true;
        }

        private Dictionary<string, List<DateTime>> CloneCache()
        {
            var result = new Dictionary<string, List<DateTime>>(StringComparer.OrdinalIgnoreCase);
            foreach (var kvp in _cache)
                result[kvp.Key] = new List<DateTime>(kvp.Value);
            return result;
        }

        private async Task<Dictionary<string, List<DateTime>>> ReadAllInternalAsync()
        {
            EnsureFile();
            try
            {
                string content = await File.ReadAllTextAsync(filePath);
                var data = JsonConvert.DeserializeObject<LogonIndexData>(content);
                var result = new Dictionary<string, List<DateTime>>(StringComparer.OrdinalIgnoreCase);
                if (data?.Entries != null)
                {
                    foreach (var kvp in data.Entries)
                    {
                        var list = kvp.Value ?? new List<DateTime>();
                        result[kvp.Key] = list
                            .Distinct()
                            .OrderBy(t => t)
                            .ToList();
                    }
                }
                return result;
            }
            catch
            {
                return new Dictionary<string, List<DateTime>>(StringComparer.OrdinalIgnoreCase);
            }
        }

        private async Task WriteAllInternalAsync(Dictionary<string, List<DateTime>> entries)
        {
            var data = new LogonIndexData { Entries = entries };
            string content = JsonConvert.SerializeObject(data, Formatting.Indented);
            string tempPath = filePath + ".tmp";
            await File.WriteAllTextAsync(tempPath, content);

            if (File.Exists(filePath))
                File.Replace(tempPath, filePath, filePath + ".bak", ignoreMetadataErrors: true);
            else
                File.Move(tempPath, filePath);
        }

        private static bool TryParseWorkDate(string key, out DateTime workDate)
        {
            int sep = key.LastIndexOf("::", StringComparison.Ordinal);
            if (sep < 0)
            {
                workDate = default;
                return false;
            }

            string datePart = key.Substring(sep + 2);
            return DateTime.TryParseExact(
                datePart,
                "yyyy-MM-dd",
                System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.None,
                out workDate);
        }

        private class LogonIndexData
        {
            [JsonProperty("entries")]
            public Dictionary<string, List<DateTime>> Entries { get; set; } =
                new Dictionary<string, List<DateTime>>(StringComparer.OrdinalIgnoreCase);
        }
    }

    public class QueuedAttendanceEvent
    {
        public string QueueId { get; set; } = string.Empty;
        public int EventId { get; set; }
        public string Username { get; set; } = string.Empty;
        public DateTime EventTime { get; set; }
        public string ComputerName { get; set; } = string.Empty;
        public string EventType { get; set; } = string.Empty;
        public int LogonType { get; set; } = 0;
        public DateTime? LoginTime { get; set; }
        public DateTime? ExpectedTimeOut { get; set; }
        public DateTime? ShutdownTime { get; set; }
        public string? ShutdownType { get; set; }
        public bool WriteRawRecord { get; set; } = true;
        public bool RawRecordDispatched { get; set; } = false;
        public bool SummaryDispatched { get; set; } = false;
        public bool IsSummaryEligible { get; set; } = true;
        public string? ShutdownGroupId { get; set; }
        public DateTime? ShutdownGroupHoldUntil { get; set; }
        public bool ShutdownGroupIsRestart { get; set; } = false;

        // Username resolution metadata (audit)
        public string UsernameResolutionSource { get; set; } = "Direct";
        public string? ResolvedUsername { get; set; }
        public string? OriginalUsername { get; set; }
        public bool IsFallback { get; set; } = false;
        public string? FallbackSource { get; set; }
        public string? Status { get; set; }
        public bool PendingUsernameResolution { get; set; } = false;

        // Persistent retry state
        public int DispatchRetryCount { get; set; } = 0;
        public DateTime? NextRetryAtUtc { get; set; }
        public string? LastDispatchError { get; set; }

        /// <summary>
        /// True kalau event 42 (Sleep) ini dipakai sebagai last-resort ShutdownTime
        /// karena tidak ada 1074/6006/4647/6008/41 di hari yang sama.
        /// Di-set saat dispatch, bukan saat enqueue — karena saat enqueue belum tentu diketahui
        /// apakah event lain akan muncul kemudian.
        /// </summary>
        public bool IsLastResort42 { get; set; } = false;

        /// <summary>
        /// True kalau login ini lebih awal dari login eligible yang sudah ada di queue
        /// untuk user+workDate yang sama (dari device lain).
        /// IsSummaryEligible = false karena sudah ada yang eligible, tapi event ini
        /// tetap perlu dispatch ke UpsertDailySummaryLoginAsync untuk patch LoginTime
        /// ke nilai yang lebih awal. Hanya berlaku skenario multi-device.
        /// Di-clear (false) setelah summary berhasil di-dispatch.
        /// </summary>
        public bool IsEarlierLoginCandidate { get; set; } = false;
    }

    public class PersistentEventQueue
    {
        private readonly string queueDirectoryPath;
        private readonly string pendingDirectoryPath;
        private readonly SemaphoreSlim fileLock = new SemaphoreSlim(1, 1);

        // ── In-memory cache ──────────────────────────────────────────────────────
        // Semua query (GroupHas6006, FindMostRecent, dll) pakai cache ini — tidak
        // perlu disk read setiap call. Cache di-init dari disk sekali di constructor,
        // lalu di-sync otomatis setiap kali ada write/delete.
        // fileLock tetap melindungi cache + disk secara bersamaan.
        private readonly Dictionary<string, QueuedAttendanceEvent> _cache =
            new Dictionary<string, QueuedAttendanceEvent>(StringComparer.OrdinalIgnoreCase);
        private bool _cacheInitialized = false;

        private static readonly TimeSpan DedupWindow = TimeSpan.FromSeconds(30);

        public PersistentEventQueue(string queueDirectoryPath)
        {
            this.queueDirectoryPath = queueDirectoryPath;
            pendingDirectoryPath = Path.Combine(queueDirectoryPath, "pending");
            EnsureQueueDirectories();
            CleanupOrphanedTempFiles();
        }

        // ── Cache helpers ────────────────────────────────────────────────────────

        /// <summary>
        /// Pastikan cache sudah di-populate dari disk. Dipanggil sekali dari dalam fileLock.
        /// Setelah ini, semua operasi baca pakai _cache langsung.
        /// </summary>
        private async Task EnsureCacheAsync()
        {
            if (_cacheInitialized) return;
            var items = await LoadAllFromDiskAsync();
            _cache.Clear();
            foreach (var item in items)
                _cache[item.QueueId] = item;
            _cacheInitialized = true;
        }

        private List<QueuedAttendanceEvent> GetCachedList()
            => _cache.Values.ToList();

        private void CachePut(QueuedAttendanceEvent item)
            => _cache[item.QueueId] = item;

        private void CacheRemove(string queueId)
            => _cache.Remove(queueId);

        public async Task<bool> EnqueueIfNotDuplicateAsync(
            QueuedAttendanceEvent item,
            CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                await EnsureCacheAsync();
                var items = GetCachedList();

                var existing = items.FirstOrDefault(x =>
                    x.EventId == item.EventId &&
                    x.Username.Equals(item.Username, StringComparison.OrdinalIgnoreCase) &&
                    x.ComputerName.Equals(item.ComputerName, StringComparison.OrdinalIgnoreCase) &&
                    AbsDiff(x.EventTime, item.EventTime) < DedupWindow);

                if (existing != null)
                {
                    if ((item.EventId == 4624 || item.EventId == 6005) && ShouldReplaceExistingLogin(existing, item))
                    {
                        item.IsSummaryEligible = existing.IsSummaryEligible;
                        item.DispatchRetryCount = existing.DispatchRetryCount;
                        item.NextRetryAtUtc = existing.NextRetryAtUtc;
                        item.LastDispatchError = existing.LastDispatchError;
                        await WriteItemInternalAsync(item);
                        await DeleteItemInternalAsync(existing.QueueId);
                        CachePut(item);
                        CacheRemove(existing.QueueId);
                        return true;
                    }

                    return false;
                }

                if (item.EventId == 4624 || item.EventId == 6005)
                {
                    string itemWorkDate = item.EventTime.ToLocalTime().ToString("yyyy-MM-dd");

                    // Cari login eligible yang sudah ada di queue untuk user+workDate ini
                    var existingEligible = items.FirstOrDefault(x =>
                        (x.EventId == 4624 || x.EventId == 6005) &&
                        x.Username.Equals(item.Username, StringComparison.OrdinalIgnoreCase) &&
                        x.EventTime.ToLocalTime().ToString("yyyy-MM-dd") == itemWorkDate &&
                        x.IsSummaryEligible);

                    bool alreadyHasLoginToday = existingEligible != null;
                    item.IsSummaryEligible = !alreadyHasLoginToday;

                    // Multi-device: kalau sudah ada login eligible tapi login baru ini lebih awal
                    // (device lain login lebih cepat tapi masuk queue belakangan — terjadi saat replay),
                    // tandai sebagai EarlierLoginCandidate agar tetap dispatch ke UpsertDailySummaryLoginAsync
                    // untuk patch LoginTime ke nilai yang lebih awal.
                    if (alreadyHasLoginToday && existingEligible != null &&
                        item.EventTime < existingEligible.EventTime)
                    {
                        item.IsEarlierLoginCandidate = true;
                    }
                }

                await WriteItemInternalAsync(item);
                CachePut(item);
                return true;
            }
            finally
            {
                fileLock.Release();
            }
        }

        public async Task<QueuedAttendanceEvent?> PeekAsync(CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                await EnsureCacheAsync();
                var items = GetCachedList();
                return items.Count == 0 ? null : SortQueue(items)[0];
            }
            finally
            {
                fileLock.Release();
            }
        }

        public async Task<QueuedAttendanceEvent?> PeekNextReadyAsync(DateTime utcNow, CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                await EnsureCacheAsync();
                return SortQueue(GetCachedList())
                    .FirstOrDefault(x => !x.NextRetryAtUtc.HasValue || x.NextRetryAtUtc.Value <= utcNow);
            }
            finally
            {
                fileLock.Release();
            }
        }

        public async Task<DateTime?> GetEarliestNextRetryUtcAsync(CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                await EnsureCacheAsync();
                DateTime? min = null;
                foreach (var item in _cache.Values)
                {
                    if (item.NextRetryAtUtc.HasValue &&
                        (!min.HasValue || item.NextRetryAtUtc.Value < min.Value))
                        min = item.NextRetryAtUtc.Value;
                }
                return min;
            }
            finally
            {
                fileLock.Release();
            }
        }

        /// <summary>
        /// #2: Cek apakah raw event sudah fully dispatched di queue.
        /// Pakai in-memory cache — tidak scan disk. Aman dari blocking GetAwaiter().GetResult().
        /// </summary>
        public async Task<bool> IsFullyDispatchedAsync(
            int eventId, string computerName, DateTime eventTimeUtc,
            CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                await EnsureCacheAsync();
                return _cache.Values.Any(x =>
                    x.EventId == eventId &&
                    x.ComputerName.Equals(computerName, StringComparison.OrdinalIgnoreCase) &&
                    Math.Abs((x.EventTime - eventTimeUtc).TotalSeconds) < 5 &&
                    x.RawRecordDispatched &&
                    x.SummaryDispatched);
            }
            finally
            {
                fileLock.Release();
            }
        }

        /// <summary>
        /// Cek apakah event masih ada di queue (terlepas dari dispatch status-nya).
        /// Dipakai oleh RawEventStore.CleanupOldDatesAsync untuk membedakan:
        ///   - Event sudah tidak ada di queue (sudah selesai + dihapus) → aman dihapus dari rawevents
        ///   - Event masih ada di queue tapi belum dispatched → tahan, jangan hapus rawevents
        /// </summary>
        public async Task<bool> ExistsInQueueAsync(
            int eventId, string computerName, DateTime eventTimeUtc,
            CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                await EnsureCacheAsync();
                return _cache.Values.Any(x =>
                    x.EventId == eventId &&
                    x.ComputerName.Equals(computerName, StringComparison.OrdinalIgnoreCase) &&
                    Math.Abs((x.EventTime - eventTimeUtc).TotalSeconds) < 5);
            }
            finally
            {
                fileLock.Release();
            }
        }

        /// <summary>
        /// Bulk check: returns true if ALL provided events are either fully dispatched
        /// or no longer present in the queue (already removed after dispatch).
        /// Single lock acquisition — more efficient than per-event IsFullyDispatchedAsync calls.
        /// </summary>
        public async Task<bool> AllEventsDispatchedBulkAsync(
            IEnumerable<(int EventId, string ComputerName, DateTime EventTimeUtc)> events,
            CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                await EnsureCacheAsync();

                foreach (var (eventId, computerName, eventTimeUtc) in events)
                {
                    var match = _cache.Values.FirstOrDefault(x =>
                        x.EventId == eventId &&
                        x.ComputerName.Equals(computerName, StringComparison.OrdinalIgnoreCase) &&
                        Math.Abs((x.EventTime - eventTimeUtc).TotalSeconds) < 5);

                    if (match == null)
                        continue;

                    if (!match.RawRecordDispatched || !match.SummaryDispatched)
                        return false;
                }

                return true;
            }
            finally
            {
                fileLock.Release();
            }
        }

        public async Task<bool> GroupHas6006Async(string groupId, CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                await EnsureCacheAsync();
                return _cache.Values.Any(x =>
                    x.EventId == 6006 &&
                    x.ShutdownGroupId == groupId &&
                    !x.EventType.Contains("unconfirmed", StringComparison.OrdinalIgnoreCase));
            }
            finally
            {
                fileLock.Release();
            }
        }

        /// <summary>
        /// Cek apakah group punya 6006 yang CONFIRMED (paired 1074 shutdown, bukan restart).
        /// Kalau 6006 di group hanya unconfirmed, 4647 tetap boleh dispatch summary.
        /// </summary>
        public async Task<bool> GroupHasConfirmed6006Async(string groupId, CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                await EnsureCacheAsync();
                return _cache.Values.Any(x =>
                    x.EventId == 6006 &&
                    x.ShutdownGroupId == groupId &&
                    !x.EventType.Contains("unconfirmed", StringComparison.OrdinalIgnoreCase) &&
                    !x.EventType.Contains("restart", StringComparison.OrdinalIgnoreCase) &&
                    !x.EventType.Contains("reboot", StringComparison.OrdinalIgnoreCase));
            }
            finally
            {
                fileLock.Release();
            }
        }

        /// <summary>
        /// Cek apakah ada event login/wake (4624, 6005) setelah waktu tertentu untuk device ini
        /// di workDate yang sama. Dipakai untuk validasi event 42 sebagai last-resort shutdown.
        /// Kalau ada wake setelah 42, berarti 42 bukan shutdown final.
        /// </summary>
        public async Task<bool> HasWakeEventAfterAsync(
            string computerName,
            DateTime afterTimeUtc,
            string workDate,
            CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                await EnsureCacheAsync();
                return _cache.Values.Any(x =>
                    (x.EventId == 4624 || x.EventId == 6005) &&
                    x.ComputerName.Equals(computerName, StringComparison.OrdinalIgnoreCase) &&
                    x.EventTime > afterTimeUtc &&
                    x.EventTime.ToLocalTime().ToString("yyyy-MM-dd") == workDate);
            }
            finally
            {
                fileLock.Release();
            }
        }

        public async Task<bool> Has4647InQueueAsync(
            string username,
            string computerName,
            string workDate,
            CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                await EnsureCacheAsync();
                return _cache.Values.Any(x =>
                    x.EventId == 4647 &&
                    x.Username.Equals(username, StringComparison.OrdinalIgnoreCase) &&
                    x.ComputerName.Equals(computerName, StringComparison.OrdinalIgnoreCase) &&
                    x.EventTime.ToLocalTime().ToString("yyyy-MM-dd") == workDate);
            }
            finally
            {
                fileLock.Release();
            }
        }

        public async Task<bool> Has4624Within30sAsync(
            string username,
            string computerName,
            string workDate,
            DateTime eventTimeUtc,
            int windowSeconds = 30,
            CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                await EnsureCacheAsync();
                return _cache.Values.Any(x =>
                    x.EventId == 4624 &&
                    x.Username.Equals(username, StringComparison.OrdinalIgnoreCase) &&
                    x.ComputerName.Equals(computerName, StringComparison.OrdinalIgnoreCase) &&
                    x.EventTime.ToLocalTime().ToString("yyyy-MM-dd") == workDate &&
                    eventTimeUtc >= x.EventTime &&
                    (eventTimeUtc - x.EventTime).TotalSeconds <= windowSeconds);
            }
            finally
            {
                fileLock.Release();
            }
        }

        public async Task<bool> GroupHasHigherPriorityAsync(string groupId, int thanPriority, CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                await EnsureCacheAsync();
                return _cache.Values.Any(x =>
                    x.ShutdownGroupId == groupId &&
                    !x.SummaryDispatched &&
                    GetStaticShutdownPriority(x.EventId, x.EventType) > thanPriority);
            }
            finally
            {
                fileLock.Release();
            }
        }

        private static int GetStaticShutdownPriority(int eventId, string eventType)
        {
            if (eventId == 6006)
                // FIX [6006-FALLBACK]: Sinkron dengan LoginLogoutMonitorService.GetShutdownEventPriority
                // dan SharePointIntegration.GetShutdownPriority — unconfirmed 6006 naik dari 0 ke 2.
                return eventType.Contains("unconfirmed", StringComparison.OrdinalIgnoreCase) ? 2 : 5;
            if (eventId == 1074 && !eventType.Contains("restart", StringComparison.OrdinalIgnoreCase)
                                && !eventType.Contains("reboot", StringComparison.OrdinalIgnoreCase)) return 4;
            if (eventId == 4647) return 2;
            if (eventId == 6008) return 1;
            if (eventId == 41)   return 1;
            if (eventId == 42)   return -1; // last resort, selalu di-overwrite event lain
            return 0;
        }

        public async Task RemoveByIdAsync(string queueId, CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                await EnsureCacheAsync();
                await DeleteItemInternalAsync(queueId);
                CacheRemove(queueId);
            }
            finally
            {
                fileLock.Release();
            }
        }

        public async Task UpdateDispatchStateAsync(
            string queueId,
            bool? rawRecordDispatched = null,
            bool? summaryDispatched = null,
            CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                await EnsureCacheAsync();
                // Baca dari cache dulu, fallback ke disk kalau belum ada
                if (!_cache.TryGetValue(queueId, out var item))
                    item = await ReadByIdInternalAsync(queueId);
                if (item == null)
                    return;

                if (rawRecordDispatched.HasValue)
                    item.RawRecordDispatched = rawRecordDispatched.Value;

                if (summaryDispatched.HasValue)
                    item.SummaryDispatched = summaryDispatched.Value;

                await WriteItemInternalAsync(item);
                CachePut(item);
            }
            finally
            {
                fileLock.Release();
            }
        }

        public async Task UpdateRetryStateAsync(
            string queueId,
            int retryCount,
            DateTime? nextRetryAtUtc,
            string? lastDispatchError = null,
            CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                await EnsureCacheAsync();
                if (!_cache.TryGetValue(queueId, out var item))
                    item = await ReadByIdInternalAsync(queueId);
                if (item == null)
                    return;

                item.DispatchRetryCount = retryCount;
                item.NextRetryAtUtc = nextRetryAtUtc;
                item.LastDispatchError = lastDispatchError;
                await WriteItemInternalAsync(item);
                CachePut(item);
            }
            finally
            {
                fileLock.Release();
            }
        }

        public async Task ReplaceAsync(QueuedAttendanceEvent item, CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                await EnsureCacheAsync();
                await WriteItemInternalAsync(item);
                CachePut(item);
            }
            finally
            {
                fileLock.Release();
            }
        }

        public async Task MarkGroupAsRestartAsync(string groupId, CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                await EnsureCacheAsync();
                foreach (var item in _cache.Values.Where(x => x.ShutdownGroupId == groupId && !x.ShutdownGroupIsRestart).ToList())
                {
                    item.ShutdownGroupIsRestart = true;
                    await WriteItemInternalAsync(item);
                    CachePut(item);
                }
            }
            finally
            {
                fileLock.Release();
            }
        }

        public async Task MarkGroupSummaryDispatchedAsync(string groupId, string exceptQueueId, CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                await EnsureCacheAsync();
                foreach (var item in _cache.Values.Where(x => x.ShutdownGroupId == groupId && x.QueueId != exceptQueueId && !x.SummaryDispatched).ToList())
                {
                    item.SummaryDispatched = true;
                    await WriteItemInternalAsync(item);
                    CachePut(item);
                }
            }
            finally
            {
                fileLock.Release();
            }
        }

        public async Task<int> GetCountAsync(CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                await EnsureCacheAsync();
                return _cache.Count;
            }
            finally
            {
                fileLock.Release();
            }
        }

        public async Task<List<QueuedAttendanceEvent>> GetAllAsync(CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                await EnsureCacheAsync();
                return SortQueue(GetCachedList());
            }
            finally
            {
                fileLock.Release();
            }
        }

        public async Task<string?> FindMostRecentUsernameForComputerAsync(string computerName, DateTime beforeTimeUtc, CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                await EnsureCacheAsync();
                string workDate = beforeTimeUtc.ToLocalTime().ToString("yyyy-MM-dd");
                QueuedAttendanceEvent? latest = null;
                foreach (var x in _cache.Values)
                {
                    if ((x.EventId == 4624 || x.EventId == 6005) &&
                        x.ComputerName.Equals(computerName, StringComparison.OrdinalIgnoreCase) &&
                        x.EventTime <= beforeTimeUtc &&
                        x.EventTime.ToLocalTime().ToString("yyyy-MM-dd") == workDate &&
                        !string.IsNullOrWhiteSpace(x.Username))
                    {
                        if (latest == null || x.EventTime > latest.EventTime)
                            latest = x;
                    }
                }
                return latest?.Username;
            }
            finally
            {
                fileLock.Release();
            }
        }

        public async Task<string?> FindMostRecent4624UsernameForComputerAsync(string computerName, DateTime beforeTimeUtc, CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                await EnsureCacheAsync();
                string workDate = beforeTimeUtc.ToLocalTime().ToString("yyyy-MM-dd");
                QueuedAttendanceEvent? latest = null;
                foreach (var x in _cache.Values)
                {
                    if (x.EventId == 4624 &&
                        x.ComputerName.Equals(computerName, StringComparison.OrdinalIgnoreCase) &&
                        x.EventTime <= beforeTimeUtc &&
                        x.EventTime.ToLocalTime().ToString("yyyy-MM-dd") == workDate &&
                        !string.IsNullOrWhiteSpace(x.Username))
                    {
                        if (latest == null || x.EventTime > latest.EventTime)
                            latest = x;
                    }
                }
                return latest?.Username;
            }
            finally
            {
                fileLock.Release();
            }
        }

        public async Task<(string Username, DateTime EventTime)?> FindFirst4624ForComputerWorkDateAsync(
            string computerName,
            string workDate,
            CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                await EnsureCacheAsync();
                QueuedAttendanceEvent? first = null;
                foreach (var x in _cache.Values)
                {
                    if (x.EventId == 4624 &&
                        x.ComputerName.Equals(computerName, StringComparison.OrdinalIgnoreCase) &&
                        x.EventTime.ToLocalTime().ToString("yyyy-MM-dd") == workDate &&
                        !string.IsNullOrWhiteSpace(x.Username))
                    {
                        if (first == null || x.EventTime < first.EventTime)
                            first = x;
                    }
                }
                return first == null ? null : (first.Username, first.EventTime);
            }
            finally
            {
                fileLock.Release();
            }
        }

        public async Task<(string Username, DateTime EventTime)?> FindFirst4624ForComputerWorkDateAfterAsync(
            string computerName,
            string workDate,
            DateTime notBeforeUtc,
            CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                await EnsureCacheAsync();
                QueuedAttendanceEvent? first = null;
                foreach (var x in _cache.Values)
                {
                    if (x.EventId == 4624 &&
                        x.ComputerName.Equals(computerName, StringComparison.OrdinalIgnoreCase) &&
                        x.EventTime >= notBeforeUtc &&
                        x.EventTime.ToLocalTime().ToString("yyyy-MM-dd") == workDate &&
                        !string.IsNullOrWhiteSpace(x.Username))
                    {
                        if (first == null || x.EventTime < first.EventTime)
                            first = x;
                    }
                }
                return first == null ? null : (first.Username, first.EventTime);
            }
            finally
            {
                fileLock.Release();
            }
        }
        private static bool ShouldReplaceExistingLogin(QueuedAttendanceEvent existing, QueuedAttendanceEvent incoming)
        {
            if (incoming.EventTime < existing.EventTime)
                return true;

            if (incoming.EventTime > existing.EventTime)
                return false;

            return GetLogonTypePriority(incoming.LogonType) > GetLogonTypePriority(existing.LogonType);
        }

        private static int GetLogonTypePriority(int logonType)
        {
            return logonType switch
            {
                2  => 5,
                10 => 4,
                11 => 3,
                7  => 2,
                _  => 1
            };
        }

        private static TimeSpan AbsDiff(DateTime a, DateTime b)
        {
            var diff = a - b;
            return diff < TimeSpan.Zero ? diff.Negate() : diff;
        }

        private void EnsureQueueDirectories()
        {
            Directory.CreateDirectory(queueDirectoryPath);
            Directory.CreateDirectory(pendingDirectoryPath);
        }

        private void CleanupOrphanedTempFiles()
        {
            try
            {
                foreach (string tempFile in Directory.GetFiles(pendingDirectoryPath, "*.tmp", SearchOption.TopDirectoryOnly))
                {
                    try
                    {
                        File.Delete(tempFile);
                    }
                    catch (Exception ex)
                    {
                        SafeQueueLog($"Queue temp file cleanup failed '{tempFile}': {ex.Message}", EventLogEntryType.Warning, 1042);
                    }
                }
            }
            catch (Exception ex)
            {
                SafeQueueLog($"Queue temp file scan failed in '{pendingDirectoryPath}': {ex.Message}", EventLogEntryType.Warning, 1042);
            }
        }

        // LoadAllFromDiskAsync: hanya dipanggil sekali dari EnsureCacheAsync saat init.
        // Setelah cache ter-populate, semua baca dari _cache, tidak dari disk.
        private async Task<List<QueuedAttendanceEvent>> LoadAllFromDiskAsync()
        {
            EnsureQueueDirectories();
            var items = new List<QueuedAttendanceEvent>();

            foreach (string file in Directory.GetFiles(pendingDirectoryPath, "*.json", SearchOption.TopDirectoryOnly))
            {
                try
                {
                    string content = await File.ReadAllTextAsync(file);
                    if (string.IsNullOrWhiteSpace(content))
                        continue;

                    var item = JsonConvert.DeserializeObject<QueuedAttendanceEvent>(content);
                    if (item != null && !string.IsNullOrWhiteSpace(item.QueueId))
                        items.Add(item);
                }
                catch (Exception ex)
                {
                    SafeQueueLog($"Queue file read failed '{file}': {ex.Message}", EventLogEntryType.Warning, 1042);
                }
            }

            return items;
        }

        private async Task<QueuedAttendanceEvent?> ReadByIdInternalAsync(string queueId)
        {
            string path = BuildItemPath(queueId);
            if (!File.Exists(path))
                return null;

            try
            {
                string content = await File.ReadAllTextAsync(path);
                return JsonConvert.DeserializeObject<QueuedAttendanceEvent>(content);
            }
            catch (Exception ex)
            {
                SafeQueueLog($"Queue file read failed '{path}': {ex.Message}", EventLogEntryType.Warning, 1042);
                return null;
            }
        }

        private async Task WriteItemInternalAsync(QueuedAttendanceEvent item)
        {
            EnsureQueueDirectories();
            string finalPath = BuildItemPath(item.QueueId);
            string tempPath = finalPath + ".tmp";
            string content = JsonConvert.SerializeObject(item, Formatting.Indented);
            await File.WriteAllTextAsync(tempPath, content);
            File.Move(tempPath, finalPath, overwrite: true);
        }

        private Task DeleteItemInternalAsync(string queueId)
        {
            string path = BuildItemPath(queueId);
            if (File.Exists(path))
                File.Delete(path);
            return Task.CompletedTask;
        }

        private string BuildItemPath(string queueId) => Path.Combine(pendingDirectoryPath, $"{queueId}.json");

        private static List<QueuedAttendanceEvent> SortQueue(List<QueuedAttendanceEvent> items)
            => items
                .OrderBy(x => x.EventTime)
                .ThenBy(x => x.QueueId, StringComparer.OrdinalIgnoreCase)
                .ToList();

        private static void SafeQueueLog(string message, EventLogEntryType type, int eventId)
        {
            try
            {
                EventLog.WriteEntry("Attendance-Service", message, type, eventId);
            }
            catch { }
        }
    }
}