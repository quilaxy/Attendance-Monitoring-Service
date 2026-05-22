using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace EventLogOutEmployeeService
{
    public sealed class AdminSessionCorrelationService
    {
        // ── Admin session correlation cache ──────────────────────────────────────
        // Key:   BuildAdminSessionKey(computerName, logonId)  →  "{COMPUTER}::{0xlogonid}"
        // Value: selalu true — hanya admin session yang disimpan di sini.
        // Tujuan: korelasikan 4634 logout ke 4624 admin login via Logon ID.
        //         4634 tidak membawa Elevated Token / Linked Logon ID, sehingga
        //         tanpa cache ini konteks admin hilang sepenuhnya.
        // Thread-safety: dilindungi oleh _adminSessionLock.
        private readonly Dictionary<string, bool> _adminLogonIdCache =
            new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, DateTime> _adminLogonIdExpiry =
            new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        private readonly object _adminSessionLock = new object();
        private DateTime _lastAdminCachePrune = DateTime.MinValue;
        private static readonly TimeSpan AdminSessionRetention = TimeSpan.FromHours(48);

        private readonly RawEventStore _rawEventStore;
        private readonly Action<string, EventLogEntryType, int> _logAction;

        public AdminSessionCorrelationService(
            RawEventStore rawEventStore,
            Action<string, EventLogEntryType, int> logAction)
        {
            _rawEventStore = rawEventStore;
            _logAction = logAction;
        }

        public void RegisterAdminSession(string computerName, string logonId, string? logMessage)
        {
            if (string.IsNullOrEmpty(logonId))
                return;

            string cacheKey = BuildAdminSessionKey(computerName, logonId);
            lock (_adminSessionLock)
            {
                _adminLogonIdCache[cacheKey] = true;
                _adminLogonIdExpiry[cacheKey] = DateTime.UtcNow.Add(AdminSessionRetention);
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
                if (_adminLogonIdCache.TryGetValue(cacheKey, out _) &&
                    _adminLogonIdExpiry.TryGetValue(cacheKey, out DateTime expiry) &&
                    expiry > DateTime.UtcNow)
                {
                    isAdminSession = true;
                }
                else if (_adminLogonIdCache.ContainsKey(cacheKey))
                {
                    // Entry ada tapi expired — bersihkan sekarang
                    _adminLogonIdCache.Remove(cacheKey);
                    _adminLogonIdExpiry.Remove(cacheKey);
                }
            }

            // 2. RawEventStore disk lookup — retention-based range, reboot boundary.
            if (!isAdminSession)
            {
                try
                {
                    DateTime localDate = eventTimeUtc.ToLocalTime().Date;
                    DateTime retentionCutoff = eventTimeUtc - AdminSessionRetention;

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
                            // Reboot boundary: tolak 4624 yang terlalu lama.
                            // LogonId hanya unique dalam satu boot cycle.
                            r.EventTimeUtc >= retentionCutoff);

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
        /// Bangun composite key untuk _adminLogonIdCache.
        /// Format: "{COMPUTER}::{logonid}" — case-insensitive di kedua bagian.
        /// </summary>
        private static string BuildAdminSessionKey(string computerName, string logonId)
            => $"{computerName.ToUpperInvariant()}::{logonId.ToLowerInvariant()}";

        /// <summary>
        /// Hapus entry expired dari _adminLogonIdCache.
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
            foreach (var kv in _adminLogonIdExpiry)
            {
                if (kv.Value < DateTime.UtcNow)
                    expired.Add(kv.Key);
            }

            foreach (string k in expired)
            {
                _adminLogonIdCache.Remove(k);
                _adminLogonIdExpiry.Remove(k);
            }
        }
    }
}
