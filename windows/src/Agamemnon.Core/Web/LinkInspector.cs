using System.Globalization;
using System.Text;
using Agamemnon.Core.Scanning;

namespace Agamemnon.Core.Web;

public enum LinkRisk
{
    /// <summary>Nothing wrong found.</summary>
    Safe,

    /// <summary>Worth a second look (a shortened link, an unusual ending, no encryption on a sign-in page).</summary>
    Caution,

    /// <summary>A known malware site, or a fake copy of a well-known site.</summary>
    Dangerous,
}

/// <summary>
/// One finding. <see cref="Id"/> picks the text shown to people (web.reason.&lt;id&gt;);
/// <see cref="Value"/> fills its {0}, e.g. the brand being imitated.
/// </summary>
public sealed record LinkReason(string Id, LinkRisk Risk, string? Value = null);

public sealed record LinkVerdict(string Host, IReadOnlyList<LinkReason> Reasons)
{
    public LinkRisk Risk => Reasons.Count == 0 ? LinkRisk.Safe : Reasons.Max(r => r.Risk);
}

/// <summary>A well-known site and the addresses that really belong to it.</summary>
public sealed record Brand(string Name, string Keyword, IReadOnlyList<string> Domains);

/// <summary>
/// 5.0's web protection: decides whether a link is what it claims to be, entirely on this PC.
/// The main target is phishing: addresses made to look like a bank, a shop or a sign-in page
/// (<c>paypa1.com</c>, <c>garanti-giris.com</c>, a Cyrillic “а” in <c>аpple.com</c>,
/// <c>paypal.com.account-check.top</c>), plus links to known malware sites.
/// </summary>
public static class LinkInspector
{
    public static readonly IReadOnlyList<Brand> Brands =
    [
        new("PayPal", "paypal", ["paypal.com", "paypal.me"]),
        new("Microsoft", "microsoft", ["microsoft.com", "live.com", "office.com", "microsoftonline.com", "outlook.com", "windows.com", "xbox.com", "bing.com", "msn.com", "azure.com", "skype.com"]),
        new("Outlook", "outlook", ["outlook.com", "live.com", "office.com", "microsoft.com"]),
        new("Apple", "apple", ["apple.com", "icloud.com"]),
        new("iCloud", "icloud", ["icloud.com", "apple.com"]),
        new("Google", "google", ["google.com", "google.com.tr", "gmail.com", "youtube.com", "googleusercontent.com", "gstatic.com", "googleapis.com", "withgoogle.com"]),
        new("Gmail", "gmail", ["gmail.com", "google.com"]),
        new("YouTube", "youtube", ["youtube.com", "youtu.be", "google.com"]),
        new("Amazon", "amazon", ["amazon.com", "amazon.com.tr", "amazon.de", "amazon.co.uk", "amazon.fr", "amazonaws.com", "aws.amazon.com"]),
        new("Netflix", "netflix", ["netflix.com"]),
        new("Facebook", "facebook", ["facebook.com", "fb.com", "fb.me", "meta.com"]),
        new("Instagram", "instagram", ["instagram.com"]),
        new("WhatsApp", "whatsapp", ["whatsapp.com", "whatsapp.net", "wa.me"]),
        new("Binance", "binance", ["binance.com", "binance.tr"]),
        new("Steam", "steam", ["steampowered.com", "steamcommunity.com", "steamstatic.com"]),
        new("Steam", "steamcommunity", ["steamcommunity.com"]),
        new("Discord", "discord", ["discord.com", "discord.gg", "discordapp.com"]),
        new("GitHub", "github", ["github.com", "github.io", "githubusercontent.com"]),
        new("LinkedIn", "linkedin", ["linkedin.com"]),
        new("Spotify", "spotify", ["spotify.com"]),
        new("Roblox", "roblox", ["roblox.com"]),
        new("Epic Games", "epicgames", ["epicgames.com"]),
        new("DHL", "dhl", ["dhl.com", "dhl.de", "dhl.com.tr"]),
        new("Garanti BBVA", "garanti", ["garantibbva.com.tr", "garanti.com.tr"]),
        new("Garanti BBVA", "garantibbva", ["garantibbva.com.tr"]),
        new("İş Bankası", "isbank", ["isbank.com.tr"]),
        new("Akbank", "akbank", ["akbank.com", "akbank.com.tr"]),
        new("Ziraat Bankası", "ziraat", ["ziraatbank.com.tr", "ziraat.com.tr"]),
        new("Ziraat Bankası", "ziraatbank", ["ziraatbank.com.tr"]),
        new("Yapı Kredi", "yapikredi", ["yapikredi.com.tr"]),
        new("QNB", "qnb", ["qnb.com.tr", "qnbfinansbank.com"]),
        new("Halkbank", "halkbank", ["halkbank.com.tr"]),
        new("VakıfBank", "vakifbank", ["vakifbank.com.tr"]),
        new("Denizbank", "denizbank", ["denizbank.com"]),
        new("e-Devlet", "turkiye", ["turkiye.gov.tr"]),
        new("e-Devlet", "edevlet", ["turkiye.gov.tr"]),
        new("PTT", "ptt", ["ptt.gov.tr", "pttavm.com"]),
        new("Trendyol", "trendyol", ["trendyol.com"]),
        new("Hepsiburada", "hepsiburada", ["hepsiburada.com"]),
        new("Sahibinden", "sahibinden", ["sahibinden.com"]),
        new("Papara", "papara", ["papara.com"]),
        new("Turkcell", "turkcell", ["turkcell.com.tr"]),
        new("Vodafone", "vodafone", ["vodafone.com.tr", "vodafone.com"]),
        new("Türk Telekom", "turktelekom", ["turktelekom.com.tr"]),
    ];

    /// <summary>Second-level endings where the name people recognise sits one label further left.</summary>
    private static readonly HashSet<string> CompoundSuffixes = new(StringComparer.OrdinalIgnoreCase)
    {
        "com.tr", "gov.tr", "org.tr", "net.tr", "edu.tr", "k12.tr", "bel.tr", "gen.tr", "biz.tr", "info.tr", "web.tr",
        "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.jp", "co.kr", "com.br", "com.mx", "co.in", "co.za",
        "com.cn", "com.tw", "com.de", "co.nz", "com.sg", "com.ar",
    };

    /// <summary>Endings mostly seen on throwaway scam sites (or that look like file names: .zip, .mov).</summary>
    private static readonly HashSet<string> RiskyEndings = new(StringComparer.OrdinalIgnoreCase)
    {
        "zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "click", "country", "kim", "work", "rest", "cam", "lol",
        "quest", "cfd", "sbs", "icu", "buzz", "monster", "bond", "cyou", "support", "live", "shop",
    };

    private static readonly HashSet<string> Shorteners = new(StringComparer.OrdinalIgnoreCase)
    {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly", "is.gd", "rb.gy", "shorturl.at", "ow.ly", "t.ly", "tiny.cc",
        "s.id", "rebrand.ly", "v.gd", "lnkd.in", "shorte.st", "adf.ly",
    };

    /// <summary>Words that go with a fake sign-in or payment page.</summary>
    private static readonly string[] LoginWords =
    [
        "login", "signin", "logon", "verify", "account", "password", "wallet", "billing", "payment", "giris", "dogrula",
        "hesap", "sifre", "odeme",
    ];

    /// <summary>Words scam sites add to a brand's name (login and payment, delivery, refunds, prizes).</summary>
    private static readonly string[] BaitWords =
    [
        "kargo", "teslimat", "delivery", "track", "takip", "gift", "hediye", "bonus", "prize", "odul", "online", "web", "mobil",
        "mobile", "service", "servis", "help", "yardim", "basvuru", "aidat", "ceza",
        "login", "signin", "logon", "verify", "verification", "secure", "security", "account", "update", "support", "wallet",
        "unlock", "confirm", "billing", "payment", "giris", "dogrula", "dogrulama", "hesap", "guvenlik", "destek", "sifre",
        "odeme", "iade", "kampanya", "musteri",
    ];

    public static IReadOnlyList<string> ReasonIds =>
    [
        "invalid", "knownMalware", "lookalike", "brandInName", "brandInSubdomain", "mixedScripts", "internationalName",
        "userInfo", "ipAddress", "riskyEnding", "shortener", "insecureLogin", "manySubdomains",
    ];

    /// <summary>Checks a link as typed or pasted ("example.com/x" works too).</summary>
    public static LinkVerdict Inspect(string? link, IHostBlocklist? malwareHosts = null)
    {
        string text = (link ?? string.Empty).Trim().Trim('<', '>', '"', '\'');
        if (!text.Contains("://", StringComparison.Ordinal))
        {
            text = "http://" + text;
        }

        if (!Uri.TryCreate(text, UriKind.Absolute, out Uri? uri) || uri.Scheme is not ("http" or "https") || string.IsNullOrEmpty(uri.IdnHost) || !uri.IdnHost.Contains('.', StringComparison.Ordinal) && uri.HostNameType == UriHostNameType.Dns)
        {
            return new LinkVerdict(link?.Trim() ?? string.Empty, [new LinkReason("invalid", LinkRisk.Caution)]);
        }

        return InspectUri(uri, malwareHosts);
    }

    public static LinkVerdict InspectUri(Uri uri, IHostBlocklist? malwareHosts = null)
    {
        var reasons = new List<LinkReason>();
        string asciiHost = uri.IdnHost.TrimEnd('.').ToLowerInvariant();
        string host = ToUnicode(asciiHost);

        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            // "https://www.paypal.com@evil.example/" really goes to evil.example.
            reasons.Add(new("userInfo", LinkRisk.Dangerous, host));
        }

        if (malwareHosts is not null && malwareHosts.Count > 0 && malwareHosts.IsBlocked(asciiHost))
        {
            reasons.Add(new("knownMalware", LinkRisk.Dangerous, host));
        }

        if (uri.HostNameType is UriHostNameType.IPv4 or UriHostNameType.IPv6)
        {
            reasons.Add(new("ipAddress", LinkRisk.Caution, host));
            return new LinkVerdict(host, Distinct(reasons));
        }

        string[] labels = host.Split('.');
        (string registrable, string name, string ending) = Split(labels);
        string[] subdomains = labels[..^registrable.Split('.').Length];

        if (asciiHost.Split('.').Any(l => l.StartsWith("xn--", StringComparison.Ordinal)))
        {
            reasons.Add(MixesScripts(name) ? new("mixedScripts", LinkRisk.Dangerous, host) : new("internationalName", LinkRisk.Caution, host));
        }

        Brand? official = Brands.FirstOrDefault(b => b.Domains.Any(d => IsSameOrSubdomain(host, d)));
        if (official is null)
        {
            if (Imitated(name) is { } imitated)
            {
                reasons.Add(new(imitated.Exact ? "brandInName" : "lookalike", LinkRisk.Dangerous, imitated.Brand.Name));
            }
            else if (subdomains.SelectMany(Tokens).Select(Skeleton).FirstOrDefault(t => Brands.Any(b => b.Keyword == t && t.Length >= 4)) is { } keyword)
            {
                // "paypal.com.account-check.top" and "garanti.giris-yap.com" are fakes; "github.mycompany.com" may well be real.
                bool bait = labels.SelectMany(Tokens).Select(Skeleton).Any(t => IsBait(t) || BaitWords.Any(w => w.Length >= 5 && t.Contains(w, StringComparison.Ordinal)))
                            || subdomains.Any(l => l is "com" or "net" or "org" or "tr") || RiskyEndings.Contains(ending);
                reasons.Add(new("brandInSubdomain", bait ? LinkRisk.Dangerous : LinkRisk.Caution, Brands.First(b => b.Keyword == keyword).Name));
            }
        }

        if (official is null && RiskyEndings.Contains(ending))
        {
            reasons.Add(new("riskyEnding", LinkRisk.Caution, "." + ending));
        }

        if (Shorteners.Contains(registrable))
        {
            reasons.Add(new("shortener", LinkRisk.Caution, registrable));
        }

        string lowerPath = (uri.AbsolutePath + uri.Query).ToLowerInvariant();
        if (uri.Scheme == "http" && LoginWords.Any(w => lowerPath.Contains(w, StringComparison.Ordinal) || host.Contains(w, StringComparison.Ordinal)))
        {
            reasons.Add(new("insecureLogin", LinkRisk.Caution, host));
        }

        if (labels.Length >= 6)
        {
            reasons.Add(new("manySubdomains", LinkRisk.Caution, host));
        }

        return new LinkVerdict(host, Distinct(reasons));
    }

    /// <summary>The web addresses in a piece of text (for the paste guard).</summary>
    public static IEnumerable<string> FindLinks(string? text)
    {
        if (string.IsNullOrEmpty(text) || text.Length > 64 * 1024)
        {
            yield break;
        }

        foreach (string word in text.Split([' ', '\n', '\r', '\t', '"', '\'', '<', '>', '(', ')'], StringSplitOptions.RemoveEmptyEntries))
        {
            if (word.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || word.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
                || word.StartsWith("www.", StringComparison.OrdinalIgnoreCase))
            {
                yield return word.TrimEnd('.', ',', ';', '!', '?');
            }
        }
    }

    /// <summary>
    /// The registrable domain ("garantibbva.com.tr"), the name in it people recognise
    /// ("garantibbva") and its ending ("tr").
    /// </summary>
    public static (string Registrable, string Name, string Ending) Split(string[] labels)
    {
        if (labels.Length == 1)
        {
            return (labels[0], labels[0], string.Empty);
        }

        bool compound = labels.Length >= 3 && CompoundSuffixes.Contains($"{labels[^2]}.{labels[^1]}");
        int take = compound ? 3 : 2;
        return (string.Join('.', labels[^take..]), labels[^take], labels[^1]);
    }

    /// <summary>
    /// The brand a name imitates: exactly (with extra words: "paypal-secure", "garantigiris"),
    /// or nearly (one letter changed, added or swapped; look-alike letters and digits).
    /// </summary>
    private static (Brand Brand, bool Exact)? Imitated(string name)
    {
        string skeleton = Skeleton(name);
        string[] tokens = [.. Tokens(name).Select(Skeleton)];
        foreach (Brand brand in Brands)
        {
            IEnumerable<string> officialNames = brand.Domains.Select(d => Split(d.Split('.')).Name);
            foreach (string target in officialNames.Append(brand.Keyword).Distinct())
            {
                if (target.Length < 4)
                {
                    // Short names (dhl, qnb, ptt) only count as whole words: "dhl-kargo".
                    if (tokens.Length > 1 && tokens.Contains(target) && tokens.Any(IsBait))
                    {
                        return (brand, true);
                    }

                    continue;
                }

                if (skeleton == target && name != target)
                {
                    return (brand, false); // only look-alike letters differ: "paypa1", "аpple"
                }

                if (target.Length >= 6 && skeleton != target && Distance(skeleton, target) == 1)
                {
                    return (brand, false);
                }

                if (tokens.Length > 1 && tokens.Contains(target) && tokens.Any(IsBait))
                {
                    return (brand, true);
                }

                if (skeleton != target && skeleton.Contains(target, StringComparison.Ordinal)
                    && BaitWords.Any(w => skeleton.Replace(target, string.Empty, StringComparison.Ordinal).Contains(w, StringComparison.Ordinal)))
                {
                    return (brand, true);
                }
            }
        }

        return null;
    }

    private static bool IsBait(string token) => BaitWords.Contains(token, StringComparer.Ordinal);

    private static IEnumerable<string> Tokens(string label) => label.Split(['-', '_'], StringSplitOptions.RemoveEmptyEntries);

    /// <summary>
    /// What a name looks like at a glance: lower case, Turkish and accented letters without
    /// accents, look-alike Cyrillic/Greek letters and digits turned into the Latin letter they imitate.
    /// </summary>
    public static string Skeleton(string label)
    {
        var builder = new StringBuilder(label.Length);
        foreach (char raw in label.ToLowerInvariant())
        {
            builder.Append(raw switch
            {
                '0' or 'о' or 'ο' or 'ө' => 'o',
                '1' or 'ӏ' or '|' => 'l',
                'ı' or 'і' or 'ι' => 'i',
                '3' or 'е' or 'ё' or 'ε' => 'e',
                '5' or 'ѕ' => 's',
                '4' or 'а' or 'α' => 'a',
                '7' => 't',
                '8' => 'b',
                'р' or 'ρ' => 'p',
                'с' or 'ϲ' => 'c',
                'у' or 'γ' => 'y',
                'х' or 'χ' => 'x',
                'ј' => 'j',
                'һ' => 'h',
                'ԁ' => 'd',
                'ν' => 'v',
                'ѡ' or 'ԝ' => 'w',
                'к' or 'κ' => 'k',
                'м' => 'm',
                'н' => 'h',
                'т' or 'τ' => 't',
                'в' => 'b',
                'ş' => 's',
                'ç' => 'c',
                'ğ' => 'g',
                'ü' => 'u',
                'ö' => 'o',
                _ => RemoveAccent(raw),
            });
        }

        // "rn" reads as "m" and "vv" as "w" in most fonts.
        return builder.ToString().Replace("rn", "m", StringComparison.Ordinal).Replace("vv", "w", StringComparison.Ordinal);
    }

    private static char RemoveAccent(char c)
    {
        if (c < 0x80)
        {
            return c;
        }

        string decomposed = c.ToString().Normalize(NormalizationForm.FormD);
        return decomposed.Length > 0 && decomposed[0] < 0x80 ? decomposed[0] : c;
    }

    /// <summary>Latin letters mixed with Cyrillic or Greek ones in one name: a classic trick.</summary>
    private static bool MixesScripts(string label)
    {
        bool latin = label.Any(c => c is >= 'a' and <= 'z');
        bool other = label.Any(c => c is >= 'Ͱ' and <= 'Ͽ' or >= 'Ѐ' and <= 'ӿ');
        return latin && other || other && Brands.Any(b => Skeleton(label) == b.Keyword);
    }

    private static bool IsSameOrSubdomain(string host, string domain) =>
        host.Equals(domain, StringComparison.OrdinalIgnoreCase) || host.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase);

    private static string ToUnicode(string asciiHost)
    {
        try
        {
            return new IdnMapping().GetUnicode(asciiHost);
        }
        catch (ArgumentException)
        {
            return asciiHost;
        }
    }

    /// <summary>Damerau-Levenshtein (optimal string alignment) distance.</summary>
    public static int Distance(string a, string b)
    {
        int[,] d = new int[a.Length + 1, b.Length + 1];
        for (int i = 0; i <= a.Length; i++)
        {
            d[i, 0] = i;
        }

        for (int j = 0; j <= b.Length; j++)
        {
            d[0, j] = j;
        }

        for (int i = 1; i <= a.Length; i++)
        {
            for (int j = 1; j <= b.Length; j++)
            {
                int cost = a[i - 1] == b[j - 1] ? 0 : 1;
                d[i, j] = Math.Min(Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1), d[i - 1, j - 1] + cost);
                if (i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1])
                {
                    d[i, j] = Math.Min(d[i, j], d[i - 2, j - 2] + 1);
                }
            }
        }

        return d[a.Length, b.Length];
    }

    private static List<LinkReason> Distinct(List<LinkReason> reasons) => [.. reasons.DistinctBy(r => r.Id)];
}
