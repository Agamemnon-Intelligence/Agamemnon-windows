using System.Windows;
using System.Windows.Controls;
using Agamemnon.App.ViewModels;

namespace Agamemnon.App.Views;

public partial class ScanView : UserControl
{
    public ScanView() => InitializeComponent();

    private void OnDragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    private void OnDrop(object sender, DragEventArgs e)
    {
        if (DataContext is ScanViewModel model && e.Data.GetData(DataFormats.FileDrop) is string[] paths)
        {
            _ = model.ScanDroppedAsync(paths);
        }
    }
}
