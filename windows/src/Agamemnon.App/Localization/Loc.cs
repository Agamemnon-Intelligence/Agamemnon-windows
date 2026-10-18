using System.ComponentModel;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Markup;
using Agamemnon.Core.Localization;

namespace Agamemnon.App.Localization;

/// <summary>
/// The current UI language. XAML binds to its indexer through <see cref="TrExtension"/>, so
/// switching language updates every open page at once; code uses <see cref="L"/>.
/// </summary>
public sealed class Loc : INotifyPropertyChanged
{
    private Loc()
    {
    }

    public static Loc Instance { get; } = new();

    public event PropertyChangedEventHandler? PropertyChanged;

    /// <summary>Raised after the language changes, for text that code builds (status, tray menu).</summary>
    public event EventHandler? LanguageChanged;

    public AppLanguage Language { get; private set; } = AppLanguage.English;

    public string this[string key] => Translations.Get(Language, key);

    public void SetLanguage(AppLanguage language)
    {
        if (language == Language)
        {
            return;
        }

        Language = language;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Language)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(Binding.IndexerName));
        LanguageChanged?.Invoke(this, EventArgs.Empty);
    }
}

/// <summary>Translated text for code: <c>L.T("key")</c>, or <c>L.F("key", args)</c> for text with {0} placeholders.</summary>
public static class L
{
    public static string T(string key) => Loc.Instance[key];

    public static string F(string key, params object?[] args) => string.Format(CultureInfo.CurrentCulture, Loc.Instance[key], args);
}

/// <summary><c>{l:Tr dashboard.title}</c>: text that follows the language setting live.</summary>
[MarkupExtensionReturnType(typeof(object))]
public sealed class TrExtension(string key) : MarkupExtension
{
    [ConstructorArgument("key")]
    public string Key { get; set; } = key;

    public override object ProvideValue(IServiceProvider serviceProvider) =>
        new Binding($"[{Key}]") { Source = Loc.Instance, Mode = BindingMode.OneWay }.ProvideValue(serviceProvider);
}
