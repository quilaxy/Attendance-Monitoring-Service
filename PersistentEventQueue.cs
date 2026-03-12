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
    public class QueuedAttendanceEvent
    {
        public string QueueId { get; set; } = string.Empty;
        public int EventId { get; set; }
        public string Username { get; set; } = string.Empty;
        public DateTime EventTime { get; set; }
        public string ComputerName { get; set; } = string.Empty;
        public string EventType { get; set; } = string.Empty;

        /// <summary>
        /// Logon type from Windows Security event (e.g. 2=Interactive, 7=Unlock, 10=RemoteInteractive, 11=CachedInteractive).
        /// Only relevant for EventId 4624.
        /// </summary>
        public int LogonType { get; set; } = 0;

        public DateTime? LoginTime { get; set; }
        public DateTime? ExpectedTimeOut { get; set; }
        public DateTime? ShutdownTime { get; set; }
        public string? ShutdownType { get; set; }
        public bool WriteRawRecord { get; set; } = true;
        public bool RawRecordDispatched { get; set; } = false;
        public bool SummaryDispatched { get; set; } = false;

        /// <summary>
        /// Untuk EventId 4624: true hanya kalau ini login PERTAMA hari itu untuk
        /// kombinasi Username+ComputerName. 4624 berikutnya di hari yang sama tetap
        /// masuk raw list tapi tidak trigger UpsertDailySummaryLoginAsync.
        /// Untuk semua event lain: selalu true (shutdown/logout selalu eligible).
        /// </summary>
        public bool IsSummaryEligible { get; set; } = true;
    }

    public class PersistentEventQueue
    {
        private readonly string filePath;
        private readonly SemaphoreSlim fileLock = new SemaphoreSlim(1, 1);

        /// <summary>
        /// Two events with same EventId + Username + ComputerName within this window = duplicate.
        /// Tujuan: handle Windows yang kadang nulis 2x event 4624 dalam selisih beberapa detik
        /// untuk satu login yang sama (misal dari Winlogon dan lsass secara bersamaan).
        /// Sengaja dibuat kecil (30 detik) agar unlock/login berikutnya di hari yang sama
        /// tidak ikut ter-dedup — IsSummaryEligible yang handle itu.
        /// </summary>
        private static readonly TimeSpan DedupWindow = TimeSpan.FromSeconds(30);

        public PersistentEventQueue(string filePath)
        {
            this.filePath = filePath;
            EnsureQueueFile();
        }

        /// <summary>
        /// Enqueues an event if no duplicate exists within the dedup window.
        ///
        /// Dedup rules:
        ///   - Same EventId + Username + ComputerName within 10 minutes = duplicate.
        ///   - For 4624 (Login): if new event is EARLIER than existing, replace it
        ///     (we always want the earliest login time for the day).
        ///   - For all others: first-one-wins; later duplicates are dropped.
        ///
        /// IsSummaryEligible rules for 4624:
        ///   - true  hanya kalau belum ada 4624 lain dengan Username+ComputerName+WorkDate
        ///     yang sama di queue. Ini memastikan hanya 1 row per hari di SummaryListId.
        ///   - Kalau existing 4624 di-replace (waktu lebih awal), IsSummaryEligible
        ///     dari yang lama dipertahankan supaya eligible flag tidak hilang.
        ///
        /// Returns true if the item was enqueued (or replaced), false if skipped.
        /// </summary>
        public async Task<bool> EnqueueIfNotDuplicateAsync(
            QueuedAttendanceEvent item,
            CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                List<QueuedAttendanceEvent> items = await ReadAllInternalAsync();

                var existing = items.FirstOrDefault(x =>
                    x.EventId == item.EventId &&
                    x.Username.Equals(item.Username, StringComparison.OrdinalIgnoreCase) &&
                    x.ComputerName.Equals(item.ComputerName, StringComparison.OrdinalIgnoreCase) &&
                    AbsDiff(x.EventTime, item.EventTime) < DedupWindow);

                if (existing != null)
                {
                    // Login: keep the earliest timestamp. If same timestamp, keep the more
                    // meaningful logon type (e.g. Interactive over Unlock/Cached).
                    if (item.EventId == 4624 && ShouldReplaceExistingLogin(existing, item))
                    {
                        // Pertahankan IsSummaryEligible dari yang lama — kalau yang lama
                        // adalah first-of-day, yang baru (lebih awal) juga harus eligible.
                        item.IsSummaryEligible = existing.IsSummaryEligible;
                        items.Remove(existing);
                        items.Add(item);
                        await WriteAllInternalAsync(items);
                        return true; // replaced with better candidate
                    }

                    // Everything else: skip duplicate
                    return false;
                }

                // Untuk 4624: cek apakah sudah ada 4624 lain di hari yang sama
                // untuk Username+ComputerName yang sama di queue.
                // Kalau ada → IsSummaryEligible = false (bukan first login of day).
                if (item.EventId == 4624)
                {
                    string itemWorkDate = item.EventTime.ToString("yyyy-MM-dd");
                    bool alreadyHasLoginToday = items.Any(x =>
                        x.EventId == 4624 &&
                        x.Username.Equals(item.Username, StringComparison.OrdinalIgnoreCase) &&
                        x.ComputerName.Equals(item.ComputerName, StringComparison.OrdinalIgnoreCase) &&
                        x.EventTime.ToString("yyyy-MM-dd") == itemWorkDate &&
                        x.IsSummaryEligible);

                    item.IsSummaryEligible = !alreadyHasLoginToday;
                }

                items.Add(item);
                await WriteAllInternalAsync(items);
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
                List<QueuedAttendanceEvent> items = await ReadAllInternalAsync();
                return items.Count == 0 ? null : items[0];
            }
            finally
            {
                fileLock.Release();
            }
        }

        public async Task RemoveByIdAsync(string queueId, CancellationToken cancellationToken = default)
        {
            await fileLock.WaitAsync(cancellationToken);
            try
            {
                List<QueuedAttendanceEvent> items = await ReadAllInternalAsync();
                QueuedAttendanceEvent? removed = items.FirstOrDefault(x => x.QueueId == queueId);
                items.RemoveAll(x => x.QueueId == queueId);
                await WriteAllInternalAsync(items);
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
                List<QueuedAttendanceEvent> items = await ReadAllInternalAsync();
                QueuedAttendanceEvent? item = items.FirstOrDefault(x => x.QueueId == queueId);
                if (item == null)
                    return;

                if (rawRecordDispatched.HasValue)
                    item.RawRecordDispatched = rawRecordDispatched.Value;

                if (summaryDispatched.HasValue)
                    item.SummaryDispatched = summaryDispatched.Value;

                await WriteAllInternalAsync(items);
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
                List<QueuedAttendanceEvent> items = await ReadAllInternalAsync();
                return items.Count;
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
                2  => 5, // Interactive
                10 => 4, // RemoteInteractive
                11 => 3, // CachedInteractive
                7  => 2, // Unlock
                _  => 1
            };
        }

        private static TimeSpan AbsDiff(DateTime a, DateTime b)
        {
            var diff = a - b;
            return diff < TimeSpan.Zero ? diff.Negate() : diff;
        }

        private void EnsureQueueFile()
        {
            string? directory = Path.GetDirectoryName(filePath);
            if (!string.IsNullOrWhiteSpace(directory) && !Directory.Exists(directory))
                Directory.CreateDirectory(directory);

            if (!File.Exists(filePath))
                File.WriteAllText(filePath, "[]");
        }

        private async Task<List<QueuedAttendanceEvent>> ReadAllInternalAsync()
        {
            EnsureQueueFile();

            string content = await File.ReadAllTextAsync(filePath);
            if (string.IsNullOrWhiteSpace(content))
                return new List<QueuedAttendanceEvent>();

            try
            {
                return JsonConvert.DeserializeObject<List<QueuedAttendanceEvent>>(content)
                       ?? new List<QueuedAttendanceEvent>();
            }
            catch (JsonException ex)
            {
                string backupPath = Path.Combine(
                    Path.GetDirectoryName(filePath) ?? string.Empty,
                    $"{Path.GetFileName(filePath)}.bak");

                if (File.Exists(backupPath))
                {
                    try
                    {
                        string backupContent = await File.ReadAllTextAsync(backupPath);
                        var backupItems = JsonConvert.DeserializeObject<List<QueuedAttendanceEvent>>(backupContent)
                                          ?? new List<QueuedAttendanceEvent>();

                        SafeQueueLog($"ReadAllInternalAsync recovered from backup after JsonException: {ex.Message}",
                            EventLogEntryType.Warning, 1040);

                        return backupItems;
                    }
                    catch (Exception backupEx)
                    {
                        SafeQueueLog($"ReadAllInternalAsync backup recovery failed: {backupEx.Message}",
                            EventLogEntryType.Warning, 1041);
                    }
                }

                SafeQueueLog($"ReadAllInternalAsync JSON corrupted; resetting queue content. Error: {ex.Message}",
                    EventLogEntryType.Warning, 1042);

                return new List<QueuedAttendanceEvent>();
            }
        }

        private async Task WriteAllInternalAsync(List<QueuedAttendanceEvent> items)
        {
            string content = JsonConvert.SerializeObject(items, Formatting.Indented);

            string directory = Path.GetDirectoryName(filePath) ?? string.Empty;
            string tempPath = filePath + ".tmp";
            string backupPath = Path.Combine(directory, $"{Path.GetFileName(filePath)}.bak");

            await File.WriteAllTextAsync(tempPath, content);

            if (File.Exists(filePath))
            {
                File.Replace(tempPath, filePath, backupPath, ignoreMetadataErrors: true);
                if (File.Exists(backupPath))
                    File.Delete(backupPath);
            }
            else
            {
                File.Move(tempPath, filePath);
            }
        }

        private static void SafeQueueLog(string message, EventLogEntryType type, int eventId)
        {
            try
            {
                EventLog.WriteEntry("Application", message, type, eventId);
            }
            catch
            {
                // Keep queue resilient even when EventLog provider is unavailable.
            }
        }
    }
}
