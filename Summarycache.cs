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
    /// <summary>
    /// Cache lokal persisten untuk summary keys yang sudah berhasil dikirim ke SharePoint.
    ///
    /// Tujuan: mencegah duplikat row di SummaryListId lintas service restart.
    /// Setelah service restart, queue kosong sehingga IsSummaryEligible tidak bisa
    /// mendeteksi bahwa row untuk user+workDate hari ini sudah ada.
    /// Cache ini menjawab pertanyaan itu secara lokal tanpa perlu query SharePoint.
    ///
    /// Format file (summary-cache.json):
    /// {
    ///   "keys": [
    ///     "annafi\\2026-03-12",
    ///     "kidannafi\\2026-03-12"
    ///   ]
    /// }
    ///
    /// Cleanup: entry lebih dari 7 hari otomatis dihapus. WorkDate di-parse dari
    /// key format "Username\\yyyy-MM-dd".
    /// </summary>
    public class SummaryCache
    {
        private readonly string filePath;
        private readonly SemaphoreSlim fileLock = new SemaphoreSlim(1, 1);

        /// <summary>
        /// Retention summary cache disamakan dengan retention data SharePoint (6 bulan).
        /// Tujuan: mencegah duplikat row di SummaryListId lintas service restart.
        /// Kalau cache dihapus sebelum data SharePoint dihapus (misal 7 hari), service restart
        /// di hari ke-8 tidak tahu row untuk user+workDate itu sudah ada → bisa bikin duplikat.
        /// Dengan 6 bulan: 100 user × 180 hari × ~30 byte/entry ≈ 540KB — masih sangat kecil.
        /// </summary>
        private const int RetentionMonths = 6; // must match SharePointIntegration.CleanupOldRecordsAsync

        public SummaryCache(string filePath)
        {
            this.filePath = filePath;
            EnsureFile();
        }

        /// <summary>
        /// Cek apakah summaryKey sudah ada di cache.
        /// Format key: "Username\\yyyy-MM-dd"
        /// </summary>
        public async Task<bool> ContainsAsync(string summaryKey, CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                var keys = await ReadAllInternalAsync();
                return keys.Contains(summaryKey, StringComparer.OrdinalIgnoreCase);
            }
            finally
            {
                fileLock.Release();
            }
        }

        /// <summary>
        /// Tambahkan summaryKey ke cache. Idempotent — tidak masalah kalau dipanggil
        /// berkali-kali untuk key yang sama.
        /// </summary>
        public async Task AddAsync(string summaryKey, CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                var keys = await ReadAllInternalAsync();
                if (!keys.Contains(summaryKey, StringComparer.OrdinalIgnoreCase))
                {
                    keys.Add(summaryKey);
                    await WriteAllInternalAsync(keys);
                }
            }
            finally
            {
                fileLock.Release();
            }
        }

        /// <summary>
        /// Hapus entry yang workDate-nya lebih dari RetentionMonths (6 bulan).
        /// Dipanggil dari CleanupOldRecordsTask bersamaan dengan cleanup SharePoint.
        /// Retention sengaja disamakan dengan SharePoint agar cache tidak expired
        /// sebelum data SharePoint-nya sendiri dihapus — kalau cache expired duluan,
        /// service restart bisa bikin duplikat row untuk data yang masih ada di SharePoint.
        /// </summary>
        public async Task CleanupOldEntriesAsync(CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                var keys = await ReadAllInternalAsync();
                DateTime cutoff = DateTime.Today.AddMonths(-RetentionMonths);
                int before = keys.Count;

                keys.RemoveAll(key =>
                {
                    // Key format: "Username\\yyyy-MM-dd"
                    // WorkDate adalah segmen terakhir
                    int lastSlash = key.LastIndexOf('\\');
                    if (lastSlash < 0) return false;
                    string datePart = key.Substring(lastSlash + 1);
                    return DateTime.TryParse(datePart, out DateTime d) && d.Date < cutoff;
                });

                if (keys.Count != before)
                {
                    await WriteAllInternalAsync(keys);
                    SafeLog($"[SummaryCache] Cleanup: removed {before - keys.Count} old entries. Remaining={keys.Count}",
                        EventLogEntryType.Information, 5006);
                }
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
                File.WriteAllText(filePath, JsonConvert.SerializeObject(new CacheData()));
        }

        private async Task<List<string>> ReadAllInternalAsync()
        {
            EnsureFile();
            try
            {
                string content = await File.ReadAllTextAsync(filePath);
                var data = JsonConvert.DeserializeObject<CacheData>(content);
                return data?.Keys ?? new List<string>();
            }
            catch
            {
                return new List<string>();
            }
        }

        private async Task WriteAllInternalAsync(List<string> keys)
        {
            var data = new CacheData { Keys = keys };
            string content = JsonConvert.SerializeObject(data, Formatting.Indented);

            string tempPath = filePath + ".tmp";
            await File.WriteAllTextAsync(tempPath, content);

            if (File.Exists(filePath))
                File.Replace(tempPath, filePath, filePath + ".bak", ignoreMetadataErrors: true);
            else
                File.Move(tempPath, filePath);
        }

        private static void SafeLog(string message, EventLogEntryType type, int eventId)
        {
            // 5006 (cleanup detail) adalah verbose-only
            if (!LoginLogoutMonitorService.VerboseLogging && eventId == 5006)
                return;
            try { EventLog.WriteEntry("Application", message, type, eventId); }
            catch { }
        }

        private class CacheData
        {
            [JsonProperty("keys")]
            public List<string> Keys { get; set; } = new List<string>();
        }
    }
}