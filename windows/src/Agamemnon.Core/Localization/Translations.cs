using System.Globalization;

namespace Agamemnon.Core.Localization;

public enum AppLanguage
{
    English,
    Turkish,
}

/// <summary>
/// The app's text in English and Turkish. Every key has both; the unit tests check that, that
/// both sides use the same {0}-style placeholders, and that every key the app uses exists.
/// </summary>
public static partial class Translations
{
    static Translations()
    {
        // 4.0's texts live in their own file, grouped by page like the rest.
        foreach ((string key, (string En, string Tr) text) in Table40)
        {
            Table.Add(key, text);
        }
    }

    public static IReadOnlyDictionary<string, (string En, string Tr)> All => Table;

    /// <summary>The text for <paramref name="key"/>, or the key itself if it is missing (so a gap is visible, not blank).</summary>
    public static string Get(AppLanguage language, string key) =>
        Table.TryGetValue(key, out (string En, string Tr) text)
            ? language == AppLanguage.Turkish ? text.Tr : text.En
            : key;

    /// <summary>The settings code for a language: "en" or "tr".</summary>
    public static string Code(AppLanguage language) => language == AppLanguage.Turkish ? "tr" : "en";

    /// <summary>
    /// The language for a settings code. With no choice saved yet, Turkish Windows gets Turkish
    /// and everything else English.
    /// </summary>
    public static AppLanguage Parse(string? code, CultureInfo windowsLanguage) =>
        (code?.Trim().ToUpperInvariant() ?? windowsLanguage.TwoLetterISOLanguageName.ToUpperInvariant()) switch
        {
            "TR" => AppLanguage.Turkish,
            _ => AppLanguage.English,
        };
}
