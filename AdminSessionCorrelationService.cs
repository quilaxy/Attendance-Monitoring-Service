using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace EventLogOutEmployeeService
{
    public sealed class AdminSessionCorrelationService
    {
        // ── Admin session correlation cache ──────────────────────────────────────
        // Key:   BuildAdminSessionKey(computerName, logonId)  →  "{COMPUTER}::{bootSessionId}::{0xlogonid}"
        // Value: expiry timestamp (UTC) untuk admin session.
        // Tujuan: korelasikan 4634 logout ke 4624 admin login via Logon ID.
        //         4634 tidak membawa Elevated Token / Linked Logon ID, sehingga
        //         tanpa cache ini konteks admin hilang sepenuhnya.
        // Thread-safety: dilindungi oleh _adminSessionLock.
        private readonly Dictionary<string, DateTime> _adminSessions =
            new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        private readonly object _adminSessionLock = new object();
        private DateTime _lastAdminCachePrune = DateTime.MinValue;
        private static readonly TimeSpan AdminSessionRetention = TimeSpan.FromHours(48);

        private readonly RawEventStore _rawEventStore;
        private readonly Action<string, EventLogEntryType, int> _logAction;
        private string _bootSessionId = string.Empty;
        private string _bootSessionIdPath = string.Empty;

        public AdminSessionCorrelationService(
            RawEventStore rawEventStore,
            Action<string, EventLogEntryType, int> logAction)
        {
            _rawEventStore = rawEventStore;
            _logAction = logAction;
        }

        public void InitBootSessionId(string dataDirectory)
        {
            _bootSessionIdPath = Path.Combine(dataDirectory, "boot-session-id.txt");

            if (File.Exists(_bootSessionIdPath))
                _bootSessionId = File.ReadAllText(_bootSessionIdPath).Trim();

            if (string.IsNullOrWhiteSpace(_bootSessionId))
            {
                _bootSessionId = Guid.NewGuid().ToString("N");
                File.WriteAllText(_bootSessionIdPath, _bootSessionId);
            }
        }

        // ── FIX ROOT CAUSE ──────────────────────────────────────────────────────
        //
        // SEBELUMNYA: HandleServiceStopping() memanggil InvalidateBootSession()
        // tanpa membedakan caller — baik OnStop() (service restart) maupun
        // OnShutdown() (Windows shutdown) sama-sama menghapus boot-session-id.txt.
        //
        // AKIBATNYA pada service restart:
        //   1. boot-session-id.txt dihapus saat stop.
        //   2. Saat service start ulang, GUID baru dibuat ("GUID-B").
        //   3. ReplayMissedEventsFromCheckpoint() membaca 4624 admin dari RawStore
        //      dan memanggil RegisterAdminSession(key="PC::GUID-B::0xABC") → OK.
        //   4. RetryPendingQueueOnStartupAsync() berjalan SEBELUM replay selesai.
        //      _adminSessions masih kosong → admin gate miss → event admin
        //      lolos ke SharePoint (rawListId & summaryListId).
        //
        //   Pada startup berikutnya GUID berubah lagi ("GUID-C") → semua key
        //   yang sudah ter-hydrate dengan "GUID-B" tidak lagi match → bug berulang.
        //
        // FIX: Pisahkan menjadi dua method dengan tanggung jawab berbeda:
        //
        //   InvalidateBootSessionOnWindowsShutdown()  → dipanggil HANYA dari OnShutdown().
        //     Menghapus file agar setelah Windows reboot, sesi baru mendapat GUID baru.
        //     Ini adalah satu-satunya skenario di mana invalidate memang diperlukan.
        //
        //   ClearAdminSessionCache()  → dipanggil dari OnStop() (service restart).
        //     TIDAK menghapus file — GUID dipertahankan lintas restart service.
        //     Hanya flush in-memory cache karena proses baru akan re-hydrate dari RawStore.
        //
        // Dengan pemisahan ini:
        //   - Pada service restart: GUID sama, re-hydrate dari RawStore langsung match.
        //   - Pada Windows reboot: GUID baru, sesi Windows baru benar-benar fresh.
        // ────────────────────────────────────────────────────────────────────────

        /// <summary>
        /// Hapus boot-session-id.txt — hanya dipanggil saat Windows shutdown/reboot nyata
        /// (dari <c>OnShutdown()</c>). Setelah Windows boot ulang, service akan membuat
        /// GUID baru yang merepresentasikan boot session baru secara akurat.
        ///
        /// JANGAN panggil ini dari <c>OnStop()</c> (service restart) — lihat <see cref="ClearAdminSessionCache"/>.
        /// </summary>
        public void InvalidateBootSessionOnWindowsShutdown()
        {
            try
            {
                if (!string.IsNullOrWhiteSpace(_bootSessionIdPath) && File.Exists(_bootSessionIdPath))
                    File.Delete(_bootSessionIdPath);
            }
            catch
            {
                // non-critical
            }
        }

        /// <summary>
        /// Flush in-memory admin session cache tanpa menyentuh boot-session-id.txt.
        /// Dipanggil dari <c>OnStop()</c> (service restart) agar proses baru
        /// tidak mewarisi cache yang stale.
        ///
        /// File GUID dipertahankan sehingga saat service start ulang, re-hydrate dari
        /// RawEventStore menggunakan GUID yang sama dan key lookup tetap match.
        /// </summary>
        public void ClearAdminSessionCache()
        {
            lock (_adminSessionLock)
            {
                _adminSessions.Clear();
            }
        }

        /// <summary>
        /// [OBSOLETE — jangan panggil langsung]
        /// Dipertahankan hanya untuk kompatibilitas sementara.
        /// Gunakan <see cref="InvalidateBootSessionOnWindowsShutdown"/> atau
        /// <see cref="ClearAdminSessionCache"/> sesuai konteks caller.
        /// </summary>
        [Obsolete("Use InvalidateBootSessionOnWindowsShutdown() from OnShutdown(), or ClearAdminSessionCache() from OnStop().")]
        public void InvalidateBootSession()
            => InvalidateBootSessionOnWindowsShutdown();

        public void RegisterAdminSession(string computerName, string logonId, string? logMessage)
        {
            if (string.IsNullOrEmpty(logonId))
                return;

            string cacheKey = BuildAdminSessionKey(computerName, logonId);
            lock (_adminSessionLock)
            {
                _adminSessions[cacheKey] = DateTime.UtcNow.Add(AdminSessionRetention);
                PruneAdminSessionCache();
            }

            if (!string.IsNullOrWhiteSpace(logMessage))
                _logAction(logMessage, EventLogEntryType.Information, 2041);
        }

        public bool IsAdminSession(string computerName, string logonId, DateTime eventTimeUtc, bool isReplay)
        {
            if (string.IsNullOrEmpty(logonId))
                return false;

            bool isAdminSession = false;
            string cacheKey = BuildAdminSessionKey(computerName, logonId);

            // 1. In-memory cache (fast path) — validasi expiry secara eksplisit.
            lock (_adminSessionLock)
            {
                if (_adminSessions.TryGetValue(cacheKey, out DateTime expiry))
                {
                    if (expiry > DateTime.UtcNow)
                    {
                        isAdminSession = true;
                    }
                    else
                    {
                        // Entry ada tapi expired — bersihkan sekarang
                        _adminSessions.Remove(cacheKey);
                    }
                }
            }

            // 2. RawEventStore disk lookup — retention-based range, reboot boundary.
            if (!isAdminSession)
            {
                try
                {
                    DateTime localDate = eventTimeUtc.ToLocalTime().Date;
                    DateTime retentionCutoff = eventTimeUtc - AdminSessionRetention;
                    DateTime lastBootUtc = GetLastBootUpTime();

                    // Iterasi mundur per-hari sejauh AdminSessionRetention.
                    for (int dayOffset = 0;
                         localDate.AddDays(-dayOffset) >= retentionCutoff.Date;
                         dayOffset++)
                    {
                        DateTime searchDate = localDate.AddDays(-dayOffset);
                        var rawLogins = _rawEventStore.GetEventsForDate(computerName, searchDate, 4624);
                        isAdminSession = rawLogins.Any(r =>
                            r.IsAdminLogon &&
                            !string.IsNullOrEmpty(r.LogonId) &&
                            r.LogonId.Equals(logonId, StringComparison.OrdinalIgnoreCase) &&
                            r.EventTimeUtc >= retentionCutoff &&
                            // Boot boundary: tolak 4624 sebelum boot terakhir.
                            r.EventTimeUtc >= lastBootUtc);

                        if (isAdminSession)
                            break;
                    }
                }
                catch (Exception ex)
                {
                    string correlationLabel = isReplay ? "raw replay correlation" : "correlation";
                    _logAction(
                        $"[ADMIN] RawStore lookup failed for 4634 {correlationLabel}: {ex.Message}",
                        EventLogEntryType.Warning, 2043);
                }
            }

            return isAdminSession;
        }

        /// <summary>
        /// Bangun composite key untuk _adminSessions.
        /// Format: "{COMPUTER}::{bootSessionId}::{logonid}" — case-insensitive di kedua bagian.
        /// </summary>
        private string BuildAdminSessionKey(string computerName, string logonId)
            => $"{computerName.ToUpperInvariant()}::{_bootSessionId}::{logonId.ToLowerInvariant()}";

        private static DateTime GetLastBootUpTime()
        {
            return DateTime.UtcNow - TimeSpan.FromMilliseconds(Environment.TickCount64);
        }

        /// <summary>
        /// Hapus entry expired dari _adminSessions.
        /// HARUS dipanggil di dalam _adminSessionLock.
        /// Rate-limited: maksimal sekali per 5 menit untuk menekan overhead.
        /// </summary>
        private void PruneAdminSessionCache()
        {
            // Rate-limit: prune paling sering sekali per 5 menit.
            if ((DateTime.UtcNow - _lastAdminCachePrune).TotalMinutes < 5)
                return;

            _lastAdminCachePrune = DateTime.UtcNow;

            var expired = new List<string>();
            foreach (var kv in _adminSessions)
            {
                if (kv.Value < DateTime.UtcNow)
                    expired.Add(kv.Key);
            }

            foreach (string k in expired)
                _adminSessions.Remove(k);
        }
    }
}