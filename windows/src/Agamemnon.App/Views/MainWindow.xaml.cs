using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using Agamemnon.App.Services;
using Agamemnon.App.ViewModels;

namespace Agamemnon.App.Views;

public partial class MainWindow : Window
{
    private readonly MainViewModel _model;

    public MainWindow(MainViewModel model)
    {
        InitializeComponent();
        _model = model;
        DataContext = model;
        SourceInitialized += (_, _) => DarkTitleBar.Apply(this);
        model.PropertyChanged += OnModelChanged;
        SyncNavigation();
    }

    /// <summary>When true, closing really closes; otherwise the window hides to the tray.</summary>
    public bool AllowClose { get; set; }

    protected override void OnClosing(CancelEventArgs e)
    {
        if (!AllowClose)
        {
            // Protection keeps running in the notification area.
            e.Cancel = true;
            Hide();
        }

        base.OnClosing(e);
    }

    private void OnModelChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(MainViewModel.CurrentPage))
        {
            SyncNavigation();
        }
    }

    /// <summary>Keeps the sidebar highlight in step when a page is opened from elsewhere (tray, dashboard).</summary>
    private void SyncNavigation()
    {
        string title = _model.CurrentPage.Title;
        foreach (RadioButton item in Navigation.Children.OfType<RadioButton>())
        {
            item.IsChecked = (string)item.Content == title;
        }
    }
}
