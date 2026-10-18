using System.ComponentModel;
using System.Windows;
using Agamemnon.App.Services;
using Agamemnon.App.ViewModels;

namespace Agamemnon.App.Views;

public partial class WelcomeWindow : Window
{
    private readonly WelcomeViewModel _model;
    private bool _finished;

    public WelcomeWindow(WelcomeViewModel model)
    {
        InitializeComponent();
        _model = model;
        DataContext = model;
        SourceInitialized += (_, _) => DarkTitleBar.Apply(this);
        model.Finished += (_, _) =>
        {
            _finished = true;
            Close();
        };
        Closed += (_, _) => model.Detach();
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        if (!_finished)
        {
            _model.Dismiss();
        }

        base.OnClosing(e);
    }
}
