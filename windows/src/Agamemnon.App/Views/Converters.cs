using System.Globalization;
using System.Windows;
using System.Windows.Data;
using Agamemnon.App.Services;
using Agamemnon.App.ViewModels;

namespace Agamemnon.App.Views;

/// <summary>Visible when the value is false, null, empty or zero.</summary>
public sealed class CollapsedWhenConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value switch
        {
            bool b => b,
            string s => s.Length > 0,
            int i => i != 0,
            null => false,
            _ => true,
        }
            ? Visibility.Collapsed
            : Visibility.Visible;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Visible when the value is true, non-null, non-empty or non-zero.</summary>
public sealed class VisibleWhenConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        new CollapsedWhenConverter().Convert(value, targetType, parameter, culture) is Visibility.Collapsed
            ? Visibility.Visible
            : Visibility.Collapsed;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Status colour for an activity entry.</summary>
public sealed class LevelBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is ActivityLevel level ? StatusBrushes.For(level) : StatusBrushes.Neutral;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}
