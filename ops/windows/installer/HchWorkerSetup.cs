using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Web.Script.Serialization;
using System.Windows.Forms;

[assembly: AssemblyTitle("HCH Worker Setup")]
[assembly: AssemblyCompany("HUBTECH CONSULTORIA E DESENVOLVIMENTO LTDA")]
[assembly: AssemblyProduct("HCH Editorial Worker")]
[assembly: AssemblyCopyright("Copyright © HUBTECH")]
[assembly: AssemblyVersion("3.1.0.0")]
[assembly: AssemblyFileVersion("3.1.0.0")]

namespace Hubtech.HchWorker.Setup {
  internal static class Program {
    [STAThread]
    private static void Main() {
      Application.EnableVisualStyles();
      Application.SetCompatibleTextRenderingDefault(false);
      Application.Run(new SetupForm());
    }
  }

  internal sealed class SetupForm : Form {
    private readonly TextBox url = new TextBox { Text = "https://hubtech.online" };
    private readonly TextBox node = new TextBox { Text = DefaultNodeId() };
    private readonly TextBox token = new TextBox { UseSystemPasswordChar = true };
    private readonly NumericUpDown parallelism = new NumericUpDown { Minimum = 0, Maximum = 64, Value = 0 };
    private readonly CheckBox publisherTrust = new CheckBox {
      Text = "Confio na HUBTECH como publicadora deste Worker nesta máquina.", Checked = true, AutoSize = true
    };
    private readonly Button install = new Button { Text = "Instalar Worker", Height = 34 };
    private readonly Label status = new Label { AutoSize = false, Height = 42, Text = "Pronto para instalar." };

    internal SetupForm() {
      Text = "HCH Worker — Instalação";
      Width = 560; Height = 390; FormBorderStyle = FormBorderStyle.FixedDialog;
      MaximizeBox = false; StartPosition = FormStartPosition.CenterScreen;
      var panel = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(22), ColumnCount = 1 };
      panel.Controls.Add(Title("HCH Editorial Worker"));
      panel.Controls.Add(new Label { Text = "Instala o serviço, o painel local e a identidade segura desta máquina.", AutoSize = true });
      AddField(panel, "Orquestrador", url);
      AddField(panel, "Nome deste Worker", node);
      AddField(panel, "Token de autorização", token);
      AddField(panel, "Trabalhos paralelos (0 = pausado)", parallelism);
      panel.Controls.Add(publisherTrust);
      install.Dock = DockStyle.Top; install.Click += InstallClicked;
      panel.Controls.Add(install); panel.Controls.Add(status);
      Controls.Add(panel); AcceptButton = install;
    }

    private async void InstallClicked(object sender, EventArgs e) {
      Uri endpoint;
      if (!Uri.TryCreate(url.Text.Trim(), UriKind.Absolute, out endpoint) || endpoint.Scheme != "https" ||
          !string.IsNullOrEmpty(endpoint.PathAndQuery.Trim('/')) || string.IsNullOrWhiteSpace(token.Text) || !publisherTrust.Checked) {
        MessageBox.Show("Informe uma URL HTTPS, um token válido e confirme a confiança na publicadora.", "HCH Worker", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        return;
      }
      install.Enabled = false; status.Text = "Instalando. O Windows pode solicitar confirmação administrativa…";
      try {
        var endpointValue = endpoint.GetLeftPart(UriPartial.Authority);
        var nodeValue = node.Text.Trim();
        var tokenValue = token.Text;
        var parallelismValue = Decimal.ToInt32(parallelism.Value);
        token.Text = String.Empty;
        var result = await System.Threading.Tasks.Task.Run(() =>
          Install(endpointValue, nodeValue, tokenValue, parallelismValue));
        status.Text = "Worker instalado e conectado.";
        if (MessageBox.Show("Instalação concluída. Abrir o painel local?", "HCH Worker", MessageBoxButtons.YesNo, MessageBoxIcon.Information) == DialogResult.Yes)
          Process.Start("http://127.0.0.1:4319");
        Close();
      } catch (Exception error) {
        status.Text = "A instalação não foi concluída.";
        MessageBox.Show(SafeMessage(error), "HCH Worker", MessageBoxButtons.OK, MessageBoxIcon.Error);
        install.Enabled = true;
      }
    }

    private string Install(string endpoint, string nodeId, string enrollmentToken, int parallelismValue) {
      var root = Path.Combine(Path.GetTempPath(), "hch-worker-setup-" + Guid.NewGuid().ToString("N"));
      Directory.CreateDirectory(root);
      try {
        var zipPath = Path.Combine(root, "payload.zip");
        using (var source = Assembly.GetExecutingAssembly().GetManifestResourceStream("HchWorkerPayload"))
        using (var target = File.Create(zipPath)) { source.CopyTo(target); }
        ZipFile.ExtractToDirectory(zipPath, root);
        var responsePath = Path.Combine(root, "setup-response.json");
        var response = new JavaScriptSerializer().Serialize(new {
          orchestratorUrl = endpoint, nodeId = nodeId,
          enrollmentToken = enrollmentToken, parallelism = parallelismValue,
          acceptPublisherTrust = true
        });
        WritePrivateFile(responsePath, response);
        var script = Path.Combine(root, "ops", "windows", "installer", "Install-HchWorkerPackage.ps1");
        var psi = new ProcessStartInfo {
          FileName = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"),
          Arguments = "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File " + Quote(script) +
            " -PayloadRoot " + Quote(root) + " -ResponsePath " + Quote(responsePath),
          UseShellExecute = true, Verb = "runas", WindowStyle = ProcessWindowStyle.Hidden
        };
        using (var process = Process.Start(psi)) { process.WaitForExit(); if (process.ExitCode != 0) throw new InvalidOperationException("hch-setup-install-failed:" + process.ExitCode); }
        return "ok";
      } finally { try { Directory.Delete(root, true); } catch { } }
    }

    private static void WritePrivateFile(string path, string value) {
      File.WriteAllText(path, value, new UTF8Encoding(false));
      var security = new FileSecurity();
      security.SetAccessRuleProtection(true, false);
      security.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User, FileSystemRights.FullControl, AccessControlType.Allow));
      security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl, AccessControlType.Allow));
      File.SetAccessControl(path, security);
    }
    private static Label Title(string text) { return new Label { Text = text, Font = new Font(SystemFonts.MessageBoxFont.FontFamily, 17, FontStyle.Bold), AutoSize = true }; }
    private static void AddField(TableLayoutPanel panel, string label, Control control) { panel.Controls.Add(new Label { Text = label, AutoSize = true, Padding = new Padding(0, 8, 0, 0) }); control.Dock = DockStyle.Top; panel.Controls.Add(control); }
    private static string Quote(string value) { return "\"" + value.Replace("\"", "\\\"") + "\""; }
    private static string DefaultNodeId() { var value = "windows-" + Environment.MachineName.ToLowerInvariant(); return System.Text.RegularExpressions.Regex.Replace(value, "[^a-z0-9._-]", "-"); }
    private static string SafeMessage(Exception error) { var value = error.Message ?? "hch-setup-failed"; return value.Length <= 180 ? value : "hch-setup-failed"; }
  }
}
