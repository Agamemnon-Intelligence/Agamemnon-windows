using System.Globalization;
using System.Text.RegularExpressions;
using Agamemnon.Core.Localization;
using Agamemnon.Core.Scanning;
using Agamemnon.Core.Settings;

namespace Agamemnon.Core.Tests;

public partial class TranslationTests
{
    // Short texts that are the same in both languages: names and technical terms.
    private static readonly HashSet<string> SameInBothLanguages =
    [
        "nav.dns", "nav.dnsStatus", "settings.mbKey.title",
    ];

    [Fact]
    public void Every_text_exists_in_both_languages()
    {
        foreach ((string key, (string en, string tr)) in Translations.All)
        {
            Assert.False(string.IsNullOrWhiteSpace(en), $"{key} has no English text");
            Assert.False(string.IsNullOrWhiteSpace(tr), $"{key} has no Turkish text");
            Assert.True(en != tr || SameInBothLanguages.Contains(key), $"{key} isn't translated");
        }
    }

    [Fact]
    public void Both_languages_use_the_same_placeholders()
    {
        foreach ((string key, (string en, string tr)) in Translations.All)
        {
            Assert.True(Placeholders(en).SetEquals(Placeholders(tr)), $"{key}: “{en}” and “{tr}” use different placeholders");
        }
    }

    [Theory]
    [InlineData("en-US")]
    [InlineData("tr-TR")]
    public void Every_text_formats_without_errors(string culture)
    {
        var format = CultureInfo.GetCultureInfo(culture);
        foreach ((string en, string tr) in Translations.All.Values)
        {
            object[] args = [.. Enumerable.Repeat<object>(1234.5, Placeholders(en).Count == 0 ? 0 : Placeholders(en).Max() + 1)];
            Assert.NotEmpty(string.Format(format, en, args));
            Assert.NotEmpty(string.Format(format, tr, args));
        }
    }

    [Fact]
    public void Every_key_the_app_uses_exists()
    {
        string app = Path.Combine(RepositoryRoot(), "windows", "src", "Agamemnon.App");
        var used = new SortedSet<string>(StringComparer.Ordinal);
        foreach (string file in Directory.EnumerateFiles(app, "*.*", SearchOption.AllDirectories)
                     .Where(f => (f.EndsWith(".xaml", StringComparison.Ordinal) || f.EndsWith(".cs", StringComparison.Ordinal))
                                 && !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)))
        {
            string text = File.ReadAllText(file);
            foreach (Match match in XamlKey().Matches(text).Concat(CodeKey().Matches(text)))
            {
                used.Add(match.Groups[1].Value);
            }
        }

        Assert.True(used.Count > 300, $"only found {used.Count} keys; did the patterns stop matching?");
        string[] missing = [.. used.Where(key => !Translations.All.ContainsKey(key))];
        Assert.True(missing.Length == 0, "missing translations: " + string.Join(", ", missing));
    }

    [Fact]
    public void Missing_keys_show_the_key_instead_of_nothing() =>
        Assert.Equal("no.such.key", Translations.Get(AppLanguage.Turkish, "no.such.key"));

    [Theory]
    [InlineData(null, "tr-TR", AppLanguage.Turkish)]
    [InlineData(null, "en-GB", AppLanguage.English)]
    [InlineData(null, "de-DE", AppLanguage.English)]
    [InlineData("tr", "en-US", AppLanguage.Turkish)]
    [InlineData("TR", "en-US", AppLanguage.Turkish)]
    [InlineData("en", "tr-TR", AppLanguage.English)]
    [InlineData("xx", "tr-TR", AppLanguage.English)]
    public void Chooses_the_saved_language_or_follows_Windows(string? saved, string windows, AppLanguage expected) =>
        Assert.Equal(expected, Translations.Parse(saved, CultureInfo.GetCultureInfo(windows)));

    [Fact]
    public void Language_codes_round_trip()
    {
        foreach (AppLanguage language in Enum.GetValues<AppLanguage>())
        {
            Assert.Equal(language, Translations.Parse(Translations.Code(language), CultureInfo.InvariantCulture));
        }
    }

    private static HashSet<int> Placeholders(string text) =>
        [.. Placeholder().Matches(text.Replace("{{", string.Empty, StringComparison.Ordinal)).Select(m => int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture))];

    private static string RepositoryRoot()
    {
        for (DirectoryInfo? dir = new(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            if (File.Exists(Path.Combine(dir.FullName, "windows", "Agamemnon.Windows.slnx")))
            {
                return dir.FullName;
            }
        }

        throw new DirectoryNotFoundException("Couldn't find the repository root.");
    }

    [GeneratedRegex(@"\{(\d+)(?:[:,][^}]*)?\}")]
    private static partial Regex Placeholder();

    [GeneratedRegex(@"\{l:Tr ([\w.]+)\}")]
    private static partial Regex XamlKey();

    [GeneratedRegex(@"""((?:about|activity|admin|app|autoScan|common|dashboard|dns|downloads|finding|help|nav|problem|quarantine|scan|settings|status|tray|welcome)\.[\w.]+)(?<!\.json)""")]
    private static partial Regex CodeKey();
}

public class ScanScheduleTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 18, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Off_is_never_due() =>
        Assert.False(ScanSchedule.IsDue(AutoScanFrequency.Off, null, Now));

    [Fact]
    public void Never_scanned_is_due_now()
    {
        Assert.True(ScanSchedule.IsDue(AutoScanFrequency.Weekly, null, Now));
        Assert.Equal(Now, ScanSchedule.Next(AutoScanFrequency.Weekly, null, Now));
    }

    [Theory]
    [InlineData(AutoScanFrequency.Weekly, 6, false)]
    [InlineData(AutoScanFrequency.Weekly, 7, true)]
    [InlineData(AutoScanFrequency.Daily, 0.5, false)]
    [InlineData(AutoScanFrequency.Daily, 1, true)]
    public void Due_once_the_interval_has_passed(AutoScanFrequency frequency, double daysAgo, bool due) =>
        Assert.Equal(due, ScanSchedule.IsDue(frequency, Now.AddDays(-daysAgo), Now));

    [Fact]
    public void Next_scan_is_one_interval_after_the_last()
    {
        Assert.Equal(Now.AddDays(5), ScanSchedule.Next(AutoScanFrequency.Weekly, Now.AddDays(-2), Now));
        Assert.Null(ScanSchedule.Next(AutoScanFrequency.Off, Now, Now));
    }
}
