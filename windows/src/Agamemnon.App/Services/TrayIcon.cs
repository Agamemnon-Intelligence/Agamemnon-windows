using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using Agamemnon.App.Localization;
using Agamemnon.App.Themes;

namespace Agamemnon.App.Services;

public enum NavigationTarget
{
    Dashboard,
    Scan,
    Dns,
    Downloads,
    Quarantine,
    Settings,
    About,
    Help,

    // 4.0
    Protection,
    Checkup,
}

public enum NotificationLevel
{
    Info,
    Warning,
    Threat,
}

public enum ProtectionLevel
{
    Protected,
    Warning,
    Threat,
}

/// <summary>What the tray icon shows: overall protection and the encrypted-DNS state.</summary>
public sealed record TrayState(ProtectionLevel Protection, string ProtectionText, bool DnsOn, string DnsText);

/// <summary>
/// The notification-area icon (Windows' equivalent of the Mac menu bar item). The shield's colour
/// shows overall protection; the menu shows protection and DNS status and toggles DNS.
/// Windows notifications are raised through it as well.
/// </summary>
public sealed partial class TrayIcon : IDisposable
{
    private readonly NotifyIcon _icon;
    private readonly ToolStripMenuItem _protectionItem;
    private readonly ToolStripMenuItem _dnsItem;
    private readonly ToolStripMenuItem _dnsToggle;
    private readonly ToolStripMenuItem _openItem;
    private readonly ToolStripMenuItem _scanItem;
    private readonly ToolStripMenuItem _quitItem;
    private NavigationTarget _balloonTarget = NavigationTarget.Dashboard;
    private IntPtr _iconHandle;

    public TrayIcon()
    {
        _protectionItem = new ToolStripMenuItem { Enabled = false };
        _dnsItem = new ToolStripMenuItem { Enabled = false };
        _dnsToggle = new ToolStripMenuItem(string.Empty, null, (_, _) => ToggleDnsRequested?.Invoke(this, EventArgs.Empty));
        _openItem = new ToolStripMenuItem(string.Empty, null, (_, _) => OpenRequested?.Invoke(this, NavigationTarget.Dashboard));
        _scanItem = new ToolStripMenuItem(string.Empty, null, (_, _) => QuickScanRequested?.Invoke(this, EventArgs.Empty));
        _quitItem = new ToolStripMenuItem(string.Empty, null, (_, _) => QuitRequested?.Invoke(this, EventArgs.Empty));
        var menu = new ContextMenuStrip { Renderer = new DarkRenderer(), ShowImageMargin = false };
        menu.Items.AddRange(
        [
            _protectionItem,
            _dnsItem,
            new ToolStripSeparator(),
            _openItem,
            _scanItem,
            _dnsToggle,
            new ToolStripSeparator(),
            _quitItem,
        ]);
        foreach (ToolStripItem item in menu.Items)
        {
            item.ForeColor = ColorTranslator.FromHtml(DesignTokens.TextPrimary);
        }

        _icon = new NotifyIcon { ContextMenuStrip = menu, Text = "Agamemnon", Visible = true };
        _icon.MouseClick += (_, e) =>
        {
            if (e.Button == MouseButtons.Left)
            {
                OpenRequested?.Invoke(this, NavigationTarget.Dashboard);
            }
        };
        _icon.BalloonTipClicked += (_, _) => OpenRequested?.Invoke(this, _balloonTarget);
        Update(new TrayState(ProtectionLevel.Protected, L.T("tray.starting"), false, L.T("tray.checking")));
    }

    public event EventHandler<NavigationTarget>? OpenRequested;

    public event EventHandler? QuickScanRequested;

    public event EventHandler? ToggleDnsRequested;

    public event EventHandler? QuitRequested;

    public void Update(TrayState state)
    {
        string color = state.Protection switch
        {
            ProtectionLevel.Protected => DesignTokens.StatusProtected,
            ProtectionLevel.Warning => DesignTokens.StatusWarning,
            _ => DesignTokens.StatusThreat,
        };
        SetIcon(ColorTranslator.FromHtml(color), state.DnsOn);

        // NotifyIcon.Text is limited to 127 characters.
        string tip = $"Agamemnon: {state.ProtectionText}\n{L.T("tray.dns")}: {state.DnsText}";
        _icon.Text = tip.Length > 127 ? tip[..127] : tip;
        _protectionItem.Text = $"{L.T("tray.protection")}: {state.ProtectionText}";
        _dnsItem.Text = $"{L.T("tray.dns")}: {state.DnsText}";
        _dnsToggle.Text = state.DnsOn ? L.T("tray.dnsOff") : L.T("tray.dnsOn");
        _openItem.Text = L.T("tray.open");
        _scanItem.Text = L.T("tray.quickScan");
        _quitItem.Text = L.T("tray.quit");
    }

    public void Notify(NotificationLevel level, string title, string text, NavigationTarget target)
    {
        _balloonTarget = target;
        ToolTipIcon icon = level switch
        {
            NotificationLevel.Threat => ToolTipIcon.Error,
            NotificationLevel.Warning => ToolTipIcon.Warning,
            _ => ToolTipIcon.Info,
        };
        _icon.ShowBalloonTip(10_000, title, string.IsNullOrWhiteSpace(text) ? " " : text, icon);
    }

    /// <summary>Draws the shield in the status colour, with a small padlock dot when DNS is encrypted.</summary>
    private void SetIcon(Color color, bool dnsOn)
    {
        int size = SystemInformation.SmallIconSize.Width;
        using var bitmap = new Bitmap(size, size);
        using (Graphics g = Graphics.FromImage(bitmap))
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            float s = size;
            PointF[] shield =
            [
                new(s * 0.5f, s * 0.04f), new(s * 0.92f, s * 0.18f), new(s * 0.88f, s * 0.58f),
                new(s * 0.5f, s * 0.97f), new(s * 0.12f, s * 0.58f), new(s * 0.08f, s * 0.18f),
            ];
            using var fill = new SolidBrush(color);
            g.FillPolygon(fill, shield);
            using var outline = new Pen(ColorTranslator.FromHtml(DesignTokens.Background), Math.Max(1f, s / 16f));
            g.DrawPolygon(outline, shield);
            if (dnsOn)
            {
                float d = s * 0.38f;
                using var dot = new SolidBrush(ColorTranslator.FromHtml(DesignTokens.Background));
                g.FillEllipse(dot, (s - d) / 2, s * 0.32f, d, d);
            }
        }

        IntPtr handle = bitmap.GetHicon();
        using (Icon icon = Icon.FromHandle(handle))
        {
            _icon.Icon = (Icon)icon.Clone();
        }

        if (_iconHandle != IntPtr.Zero)
        {
            DestroyIcon(_iconHandle);
        }

        _iconHandle = handle;
    }

    public void Dispose()
    {
        _icon.Visible = false;
        _icon.Dispose();
        if (_iconHandle != IntPtr.Zero)
        {
            DestroyIcon(_iconHandle);
        }
    }

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool DestroyIcon(IntPtr handle);

    private sealed class DarkRenderer() : ToolStripProfessionalRenderer(new DarkColors())
    {
        protected override void OnRenderItemText(ToolStripItemTextRenderEventArgs e)
        {
            e.TextColor = e.Item.Enabled
                ? ColorTranslator.FromHtml(DesignTokens.TextPrimary)
                : ColorTranslator.FromHtml(DesignTokens.TextSecondary);
            base.OnRenderItemText(e);
        }
    }

    private sealed class DarkColors : ProfessionalColorTable
    {
        private static Color Panel => ColorTranslator.FromHtml(DesignTokens.Panel);

        private static Color Hover => ColorTranslator.FromHtml(DesignTokens.Button);

        private static Color Border => ColorTranslator.FromHtml(DesignTokens.Border);

        public override Color ToolStripDropDownBackground => Panel;

        public override Color MenuBorder => Border;

        public override Color MenuItemBorder => Hover;

        public override Color MenuItemSelected => Hover;

        public override Color MenuItemSelectedGradientBegin => Hover;

        public override Color MenuItemSelectedGradientEnd => Hover;

        public override Color SeparatorDark => Border;

        public override Color SeparatorLight => Border;

        public override Color ImageMarginGradientBegin => Panel;

        public override Color ImageMarginGradientMiddle => Panel;

        public override Color ImageMarginGradientEnd => Panel;
    }
}

/// <summary>Raises Windows notifications through the tray icon.</summary>
public sealed class Notifier(TrayIcon tray)
{
    public void Show(NotificationLevel level, string title, string text, NavigationTarget target) =>
        System.Windows.Application.Current.Dispatcher.BeginInvoke(() => tray.Notify(level, title, text, target));
}
