using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Agamemnon.Core.Scanning;

namespace Agamemnon.Core.Reputation;

public interface IHashLookup
{
    string Name { get; }

    bool IsConfigured { get; }

    /// <summary>Returns a detection when the hash is known bad, null when unknown or clean.</summary>
    Task<Detection?> LookupAsync(string sha256, CancellationToken cancellationToken);
}

public sealed class QuotaExceededException(string service) : Exception($"{service} rate limit reached.");

/// <summary>
/// abuse.ch MalwareBazaar. Only the SHA-256 is sent, never the file. abuse.ch requires a free
/// Auth-Key (https://auth.abuse.ch/) for API access.
/// </summary>
public sealed class MalwareBazaarClient(HttpClient http, Func<string?> authKey) : IHashLookup
{
    private static readonly Uri Endpoint = new("https://mb-api.abuse.ch/api/v1/");

    public string Name => "MalwareBazaar";

    public bool IsConfigured => !string.IsNullOrWhiteSpace(authKey());

    public async Task<Detection?> LookupAsync(string sha256, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, Endpoint)
        {
            Content = new FormUrlEncodedContent([new("query", "get_info"), new("hash", sha256)]),
        };
        request.Headers.Add("Auth-Key", authKey());
        using HttpResponseMessage response = await http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.TooManyRequests)
        {
            throw new QuotaExceededException(Name);
        }

        if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
        {
            throw new HttpRequestException("MalwareBazaar rejected the Auth-Key. Check it in Settings.");
        }

        response.EnsureSuccessStatusCode();
        MbResponse? body = await response.Content.ReadFromJsonAsync(ReputationJson.Default.MbResponse, cancellationToken).ConfigureAwait(false);
        return Interpret(body);
    }

    internal static Detection? Interpret(MbResponse? body)
    {
        if (body?.QueryStatus != "ok" || body.Data is not { Count: > 0 } data)
        {
            return body?.QueryStatus switch
            {
                null or "ok" or "hash_not_found" or "no_results" => null,
                "unknown_auth_key" => throw new HttpRequestException("MalwareBazaar rejected the Auth-Key. Check it in Settings."),
                string other => throw new HttpRequestException($"MalwareBazaar: {other}"),
            };
        }

        MbSample sample = data[0];
        string name = string.IsNullOrWhiteSpace(sample.Signature) ? "Known malware sample" : sample.Signature!;
        string? tags = sample.Tags is { Count: > 0 } t ? "Tags: " + string.Join(", ", t) : null;
        return new Detection("MalwareBazaar", name, Severity.Malicious, tags);
    }
}

/// <summary>VirusTotal v3 file report lookup with the user's own API key. Only the SHA-256 is sent.</summary>
public sealed class VirusTotalClient(HttpClient http, Func<string?> apiKey) : IHashLookup
{
    public string Name => "VirusTotal";

    public bool IsConfigured => !string.IsNullOrWhiteSpace(apiKey());

    public async Task<Detection?> LookupAsync(string sha256, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri($"https://www.virustotal.com/api/v3/files/{sha256}"));
        request.Headers.Add("x-apikey", apiKey());
        using HttpResponseMessage response = await http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        switch (response.StatusCode)
        {
            case HttpStatusCode.NotFound:
                return null;
            case HttpStatusCode.TooManyRequests:
                throw new QuotaExceededException(Name);
            case HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden:
                throw new HttpRequestException("VirusTotal rejected the API key. Check it in Settings.");
        }

        response.EnsureSuccessStatusCode();
        VtResponse? body = await response.Content.ReadFromJsonAsync(ReputationJson.Default.VtResponse, cancellationToken).ConfigureAwait(false);
        return Interpret(body);
    }

    internal static Detection? Interpret(VtResponse? body)
    {
        VtAttributes? attributes = body?.Data?.Attributes;
        VtStats? stats = attributes?.LastAnalysisStats;
        if (stats is null)
        {
            return null;
        }

        int engines = stats.Malicious + stats.Suspicious + stats.Undetected + stats.Harmless;
        string label = attributes!.PopularThreatClassification?.SuggestedThreatLabel is { Length: > 0 } l ? l : "Flagged by antivirus engines";
        string detail = $"{stats.Malicious} of {engines} engines flagged this file as malicious";
        if (stats.Malicious >= 5)
        {
            return new Detection("VirusTotal", label, Severity.Malicious, detail);
        }

        if (stats.Malicious >= 1 || stats.Suspicious >= 3)
        {
            return new Detection("VirusTotal", label, Severity.Suspicious, detail);
        }

        return null;
    }
}

/// <summary>
/// Runs the configured hash lookups for risky file types, with a 24-hour cache and per-service
/// rate limiting (VirusTotal's free tier allows 4 lookups a minute).
/// </summary>
public sealed class HashReputationEngine : IScanEngine
{
    private readonly IReadOnlyList<(IHashLookup Lookup, RateLimiter Limiter)> _lookups;
    private readonly ConcurrentDictionary<string, (DateTimeOffset At, Detection? Result)> _cache = new(StringComparer.OrdinalIgnoreCase);
    private readonly TimeProvider _time;

    public HashReputationEngine(IEnumerable<(IHashLookup Lookup, int PerMinute)> lookups, TimeProvider? time = null)
    {
        _time = time ?? TimeProvider.System;
        _lookups = [.. lookups.Select(l => (l.Lookup, new RateLimiter(l.PerMinute, _time)))];
    }

    public string Name => "Hash reputation";

    public Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken)
    {
        string[] configured = [.. _lookups.Where(l => l.Lookup.IsConfigured).Select(l => l.Lookup.Name)];
        return Task.FromResult(configured.Length == 0
            ? new EngineStatus(false, "Add a MalwareBazaar or VirusTotal key in Settings to enable hash lookups.")
            : new EngineStatus(true, string.Join(" + ", configured)));
    }

    public async Task<IReadOnlyList<EngineResult>> ScanAsync(IReadOnlyList<ScanTarget> batch, CancellationToken cancellationToken)
    {
        var results = new EngineResult[batch.Count];
        for (int i = 0; i < batch.Count; i++)
        {
            ScanTarget target = batch[i];
            if (!FileClassifier.IsRiskyKind(target.Kind) || target.Size == 0)
            {
                results[i] = EngineResult.Clean;
                continue;
            }

            var detections = new List<Detection>();
            var errors = new List<string>();
            foreach ((IHashLookup lookup, RateLimiter limiter) in _lookups)
            {
                if (!lookup.IsConfigured)
                {
                    continue;
                }

                string key = lookup.Name + ":" + target.Sha256;
                if (_cache.TryGetValue(key, out var cached) && _time.GetUtcNow() - cached.At < TimeSpan.FromHours(24))
                {
                    if (cached.Result is not null)
                    {
                        detections.Add(cached.Result);
                    }

                    continue;
                }

                if (!limiter.TryAcquire())
                {
                    errors.Add($"{lookup.Name}: skipped, rate limit reached");
                    continue;
                }

                try
                {
                    Detection? detection = await lookup.LookupAsync(target.Sha256, cancellationToken).ConfigureAwait(false);
                    _cache[key] = (_time.GetUtcNow(), detection);
                    if (detection is not null)
                    {
                        detections.Add(detection);
                    }
                }
                catch (QuotaExceededException ex)
                {
                    limiter.Exhaust();
                    errors.Add(ex.Message);
                }
                catch (Exception ex) when (ex is HttpRequestException or JsonException
                                           || (ex is TaskCanceledException && !cancellationToken.IsCancellationRequested))
                {
                    errors.Add($"{lookup.Name}: {ex.Message}");
                }
            }

            results[i] = new EngineResult(detections, errors.Count == 0 ? null : string.Join("; ", errors));
        }

        return results;
    }

    /// <summary>Fixed one-minute window limiter.</summary>
    private sealed class RateLimiter(int perMinute, TimeProvider time)
    {
        private readonly Lock _gate = new();
        private DateTimeOffset _windowStart = DateTimeOffset.MinValue;
        private int _used;

        public bool TryAcquire()
        {
            lock (_gate)
            {
                DateTimeOffset now = time.GetUtcNow();
                if (now - _windowStart >= TimeSpan.FromMinutes(1))
                {
                    _windowStart = now;
                    _used = 0;
                }

                if (_used >= perMinute)
                {
                    return false;
                }

                _used++;
                return true;
            }
        }

        public void Exhaust()
        {
            lock (_gate)
            {
                _used = perMinute;
            }
        }
    }
}

internal sealed record MbResponse(
    [property: JsonPropertyName("query_status")] string? QueryStatus,
    [property: JsonPropertyName("data")] List<MbSample>? Data);

internal sealed record MbSample(
    [property: JsonPropertyName("sha256_hash")] string? Sha256,
    [property: JsonPropertyName("signature")] string? Signature,
    [property: JsonPropertyName("tags")] List<string>? Tags);

internal sealed record VtResponse([property: JsonPropertyName("data")] VtData? Data);

internal sealed record VtData([property: JsonPropertyName("attributes")] VtAttributes? Attributes);

internal sealed record VtAttributes(
    [property: JsonPropertyName("last_analysis_stats")] VtStats? LastAnalysisStats,
    [property: JsonPropertyName("popular_threat_classification")] VtClassification? PopularThreatClassification);

internal sealed record VtStats(
    [property: JsonPropertyName("malicious")] int Malicious,
    [property: JsonPropertyName("suspicious")] int Suspicious,
    [property: JsonPropertyName("undetected")] int Undetected,
    [property: JsonPropertyName("harmless")] int Harmless);

internal sealed record VtClassification([property: JsonPropertyName("suggested_threat_label")] string? SuggestedThreatLabel);

[JsonSerializable(typeof(MbResponse))]
[JsonSerializable(typeof(VtResponse))]
internal sealed partial class ReputationJson : JsonSerializerContext;
