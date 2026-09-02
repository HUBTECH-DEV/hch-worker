using System.Diagnostics;
using System.Net.Mail;
using System.Windows;
using Hch.Worker.IPC.Contracts;
using Microsoft.Win32;

namespace Hch.Worker.Tray;

public partial class OnboardingWindow : Window
{
    private readonly NamedPipeWorkerClient client;
    private UserSshPublicKey? userKey;
    private string? authorizationCorrelationId;
    private string? registeredUserSshKeyId;
    private string? registeredUserSshKeyFingerprint;
    private string? selfEnrollmentRequestId;
    private OperationalEnrollmentContextPayload? operationalEnrollmentContext;

    public OnboardingWindow(NamedPipeWorkerClient client)
    {
        this.client = client;
        InitializeComponent();
        Loaded += OnboardingWindow_Loaded;
    }

    protected override void OnClosed(EventArgs e)
    {
        PasswordInput.Clear();
        VisiblePasswordInput.Clear();
        if (authorizationCorrelationId is string correlationId)
        {
            authorizationCorrelationId = null;
            _ = HihDesktopClient.RevokeSilentlyAsync(correlationId);
        }
        base.OnClosed(e);
    }

    private async void OnboardingWindow_Loaded(object sender, RoutedEventArgs e)
    {
        try
        {
            _ = await client.PauseAsync().ConfigureAwait(true);
        }
        catch (Exception error) when (error is IOException or TimeoutException or WorkerControlClientException)
        {
            // A fresh service is already Paused/Drain and may reject a redundant
            // pause while bootstrap is incomplete. Verification below is decisive.
        }

        await VerifyServiceAsync().ConfigureAwait(true);
    }

    private async void VerifyService_Click(object sender, RoutedEventArgs e) =>
        await VerifyServiceAsync().ConfigureAwait(true);

    private async Task VerifyServiceAsync()
    {
        try
        {
            var snapshot = await client.GetSnapshotAsync().ConfigureAwait(true);
            ServiceStatus.Text = snapshot.ServiceState;
            ConnectionStatus.Text = snapshot.LastHeartbeatAt is null
                ? "Serviço acessível; heartbeat ainda não recebido"
                : $"Conectado · último heartbeat {snapshot.LastHeartbeatAt:O}";
            OperationalStatus.Text = snapshot.OperationalState;
            WizardStatus.Text = snapshot.AcceptingClaims
                ? "Atenção: bloqueando novos claims durante o onboarding."
                : "Serviço acessível e sem novos claims.";
        }
        catch (Exception error) when (error is IOException or TimeoutException or WorkerControlClientException)
        {
            ServiceStatus.Text = "Não disponível";
            ConnectionStatus.Text = "Não disponível";
            OperationalStatus.Text = "Paused/Drain solicitado";
            WizardStatus.Text = "O serviço não respondeu. Verifique a instalação antes de avançar.";
        }
    }

    private async void BrowserLogin_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            AccountStatus.Text = "Aguardando autorização no navegador do sistema…";
            var result = await HihDesktopClient.AuthorizeWithBrowserAsync().ConfigureAwait(true);
            authorizationCorrelationId = result.CorrelationId;
            AccountStatus.Text = $"Conta validada: {result.DisplayEmail}. Sessão válida até {result.ExpiresAt.LocalDateTime:t}.";
            EnrollmentAccountStatus.Text = "Sessão HIH validada com PKCE";
        }
        catch (HihDesktopAuthenticationException error)
        {
            AccountStatus.Text = error.UserMessage;
        }
    }

    private async void NativeLogin_Click(object sender, RoutedEventArgs e)
    {
        string email = EmailInput.Text.Trim();
        if (!IsValidEmail(email))
        {
            AccountStatus.Text = "Informe um endereço de e-mail válido.";
            return;
        }

        string password = ShowPassword.IsChecked == true ? VisiblePasswordInput.Text : PasswordInput.Password;
        if (string.IsNullOrEmpty(password))
        {
            AccountStatus.Text = "Informe a senha.";
            return;
        }

        try
        {
            // The password is intentionally not sent through IPC. The native HIH
            // client owns the direct TLS exchange and returns only a short-lived,
            // revocable authorization handle.
            var result = await HihDesktopClient.AuthenticateAsync(email, password).ConfigureAwait(true);
            authorizationCorrelationId = result.CorrelationId;
            AccountStatus.Text = $"Conta validada: {result.DisplayEmail}.";
            EnrollmentAccountStatus.Text = "Sessão HIH validada";
        }
        catch (HihDesktopAuthenticationException error)
        {
            AccountStatus.Text = error.UserMessage;
        }
        finally
        {
            password = string.Empty;
            PasswordInput.Clear();
            VisiblePasswordInput.Clear();
        }
    }

    private void ShowPassword_Changed(object sender, RoutedEventArgs e)
    {
        if (ShowPassword.IsChecked == true)
        {
            VisiblePasswordInput.Text = PasswordInput.Password;
            PasswordInput.Clear();
            VisiblePasswordInput.Visibility = Visibility.Visible;
            PasswordInput.Visibility = Visibility.Collapsed;
            _ = VisiblePasswordInput.Focus();
        }
        else
        {
            PasswordInput.Password = VisiblePasswordInput.Text;
            VisiblePasswordInput.Clear();
            PasswordInput.Visibility = Visibility.Visible;
            VisiblePasswordInput.Visibility = Visibility.Collapsed;
            _ = PasswordInput.Focus();
        }
    }

    private async void ForgotPassword_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            OpenExternal(await HihDesktopClient.GetPasswordRecoveryUriAsync().ConfigureAwait(true));
        }
        catch (HihDesktopAuthenticationException error)
        {
            AccountStatus.Text = error.UserMessage;
        }
    }

    private async void CreateAccount_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            OpenExternal(await HihDesktopClient.GetCreateAccountUriAsync().ConfigureAwait(true));
        }
        catch (HihDesktopAuthenticationException error)
        {
            AccountStatus.Text = error.UserMessage;
        }
    }

    private async void GenerateRecommendedKey_Click(object sender, RoutedEventArgs e)
    {
        string nodeId = TrayConfiguration.ResolveNodeId();
        await GenerateKeyAsync(UserSshKeyManager.RecommendedPrivateKeyPath(nodeId), nodeId).ConfigureAwait(true);
    }

    private async void GenerateCustomKey_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Title = "Escolher caminho da chave privada Ed25519",
            FileName = $"id_ed25519_hch_{TrayConfiguration.ResolveNodeId()}",
            Filter = "Chave privada Ed25519|*.*",
            AddExtension = false,
            OverwritePrompt = true,
        };
        if (dialog.ShowDialog(this) == true)
        {
            await GenerateKeyAsync(dialog.FileName, TrayConfiguration.ResolveNodeId()).ConfigureAwait(true);
        }
    }

    private async Task GenerateKeyAsync(string privatePath, string nodeId)
    {
        try
        {
            userKey = await UserSshKeyManager.GenerateAsync(privatePath, nodeId).ConfigureAwait(true);
            ShowUserKey(userKey);
            WizardStatus.Text = "Chave do usuário criada com ACL exclusiva e pronta para registro.";
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException or InvalidOperationException)
        {
            WizardStatus.Text = $"Não foi possível criar a chave: {SanitizeKeyError(error.Message)}";
        }
    }

    private async void UseExistingKey_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Selecionar chave pública Ed25519 existente",
            Filter = "Chave pública (*.pub)|*.pub|Todos os arquivos|*.*",
            CheckFileExists = true,
            Multiselect = false,
        };
        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        try
        {
            userKey = await UserSshKeyManager.ReadExistingAsync(dialog.FileName).ConfigureAwait(true);
            ShowUserKey(userKey);
            WizardStatus.Text = "Chave pública existente validada como Ed25519.";
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException or System.Security.Cryptography.CryptographicException)
        {
            WizardStatus.Text = $"A chave selecionada não é válida: {SanitizeKeyError(error.Message)}";
        }
    }

    private async void Enroll_Click(object sender, RoutedEventArgs e)
    {
        if (authorizationCorrelationId is null)
        {
            EnrollmentRequestStatus.Text = "Autentique a conta HIH primeiro.";
            return;
        }

        if (userKey is null)
        {
            EnrollmentRequestStatus.Text = "Gere ou selecione uma chave pública Ed25519 primeiro.";
            return;
        }

        try
        {
            operationalEnrollmentContext ??= await client.BeginEnrollmentAsync(
                "operational-key-proof-v1").ConfigureAwait(true);
            var result = await HihDesktopClient.RegisterPublicKeyAsync(
                authorizationCorrelationId,
                userKey,
                operationalEnrollmentContext.NodeId).ConfigureAwait(true);
            registeredUserSshKeyId = result.UserSshKeyId;
            registeredUserSshKeyFingerprint = result.UserSshKeyFingerprint;
            selfEnrollmentRequestId ??= Guid.NewGuid().ToString("D");
            EnrollmentRequestStatus.Text = result.Status;
            EnrollmentKeyStatus.Text = $"Registrada no HIH · {result.UserSshKeyFingerprint}";
        }
        catch (HihDesktopAuthenticationException error)
        {
            EnrollmentRequestStatus.Text = error.UserMessage;
        }
        catch (WorkerControlClientException error)
        {
            EnrollmentRequestStatus.Text = EnrollmentErrorMessage(error.Code);
        }
        catch (Exception error) when (error is IOException or TimeoutException)
        {
            EnrollmentRequestStatus.Text = "O serviço do Worker não respondeu ao início do enrollment.";
        }
    }

    private async void CompleteEnrollment_Click(object sender, RoutedEventArgs e)
    {
        if (registeredUserSshKeyId is null || registeredUserSshKeyFingerprint is null)
        {
            EnrollmentRequestStatus.Text = "Registre primeiro a chave pública do usuário no HIH.";
            return;
        }

        if (authorizationCorrelationId is null)
        {
            EnrollmentRequestStatus.Text = "A sessão HIH expirou. Entre novamente para autorizar o Worker.";
            return;
        }

        try
        {
            operationalEnrollmentContext ??= await client.BeginEnrollmentAsync(
                "operational-key-proof-v1").ConfigureAwait(true);
            selfEnrollmentRequestId ??= Guid.NewGuid().ToString("D");
            using HchSelfEnrollmentToken token = await HihDesktopClient.IssueSelfEnrollmentTokenAsync(
                authorizationCorrelationId,
                selfEnrollmentRequestId,
                operationalEnrollmentContext.NodeId,
                registeredUserSshKeyId,
                registeredUserSshKeyFingerprint).ConfigureAwait(true);
            OperationalEnrollmentCompletedPayload result = await client.SubmitEnrollmentTokenAsync(
                token.TokenUtf8,
                registeredUserSshKeyId,
                registeredUserSshKeyFingerprint).ConfigureAwait(true);
            EnrollmentRequestStatus.Text =
                $"Enrollment concluído · chave operacional ativa · proprietário {result.OwnerEmail}.";
            WizardStatus.Text = "Identidade operacional vinculada. O Worker permanece em Paused/Drain.";
            if (authorizationCorrelationId is string correlationId)
            {
                await HihDesktopClient.RevokeAsync(correlationId).ConfigureAwait(true);
                authorizationCorrelationId = null;
            }
        }
        catch (HihDesktopAuthenticationException error)
        {
            EnrollmentRequestStatus.Text = error.UserMessage;
        }
        catch (WorkerControlClientException error)
        {
            EnrollmentRequestStatus.Text = EnrollmentErrorMessage(error.Code);
        }
        catch (Exception error) when (error is IOException or TimeoutException)
        {
            EnrollmentRequestStatus.Text =
                "O serviço não respondeu. O token não foi salvo; repita com o mesmo token para reconciliação idempotente.";
        }
    }

    private async void ValidateFinal_Click(object sender, RoutedEventArgs e) =>
        await ValidateFinalAsync().ConfigureAwait(true);

    private async Task ValidateFinalAsync()
    {
        try
        {
            var snapshot = await client.GetSnapshotAsync().ConfigureAwait(true);
            FinalTrustStatus.Text = snapshot.TrustStatus;
            FinalManifestStatus.Text = snapshot.ManifestStatus;
            FinalReadyStatus.Text = snapshot.Ready ? "Pronto e pausado" : "Ainda não pronto";
            WizardStatus.Text = snapshot.Ready
                ? "Onboarding validado. Concluir manterá o Worker pausado."
                : "A validação ainda não foi concluída pelo serviço.";
        }
        catch (Exception error) when (error is IOException or TimeoutException or WorkerControlClientException)
        {
            FinalTrustStatus.Text = "Não disponível";
            FinalManifestStatus.Text = "Não disponível";
            FinalReadyStatus.Text = "Não disponível";
            WizardStatus.Text = "O serviço não respondeu à validação.";
        }
    }

    private async void Next_Click(object sender, RoutedEventArgs e)
    {
        if (Steps.SelectedIndex < Steps.Items.Count - 1)
        {
            Steps.SelectedIndex++;
            UpdateNavigation();
        }

        if (Steps.SelectedIndex == Steps.Items.Count - 1)
        {
            await ValidateFinalAsync().ConfigureAwait(true);
        }
    }

    private void Back_Click(object sender, RoutedEventArgs e)
    {
        if (Steps.SelectedIndex > 0)
        {
            Steps.SelectedIndex--;
            UpdateNavigation();
        }
    }

    private void Finish_Click(object sender, RoutedEventArgs e)
    {
        PasswordInput.Clear();
        VisiblePasswordInput.Clear();
        DialogResult = true;
    }

    private async void Cancel_Click(object sender, RoutedEventArgs e)
    {
        PasswordInput.Clear();
        VisiblePasswordInput.Clear();
        if (authorizationCorrelationId is string correlationId)
        {
            authorizationCorrelationId = null;
            await HihDesktopClient.RevokeSilentlyAsync(correlationId).ConfigureAwait(true);
        }
        DialogResult = false;
    }

    private void UpdateNavigation()
    {
        BackButton.IsEnabled = Steps.SelectedIndex > 0;
        bool last = Steps.SelectedIndex == Steps.Items.Count - 1;
        NextButton.Visibility = last ? Visibility.Collapsed : Visibility.Visible;
        FinishButton.Visibility = last ? Visibility.Visible : Visibility.Collapsed;
    }

    private void ShowUserKey(UserSshPublicKey value)
    {
        registeredUserSshKeyId = null;
        registeredUserSshKeyFingerprint = null;
        selfEnrollmentRequestId = null;
        KeyAlgorithm.Text = value.Algorithm;
        KeyPath.Text = value.PrivateKeyPath;
        KeyFingerprint.Text = value.Fingerprint;
        PublicKey.Text = value.PublicKey;
        EnrollmentKeyStatus.Text = $"Validada localmente · {value.Fingerprint} · registro no HIH pendente";
    }

    private static bool IsValidEmail(string value)
    {
        try
        {
            var parsed = new MailAddress(value);
            return value.Length <= 254 && string.Equals(parsed.Address, value, StringComparison.OrdinalIgnoreCase);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static string SanitizeKeyError(string value) => value.Length <= 120 ? value : value[..120];

    private static string EnrollmentErrorMessage(string code) => code switch
    {
        "enrollment-unauthorized" => "Token inexistente, expirado, revogado ou ainda não autorizado no HCH.",
        "enrollment-forbidden" or "challenge-not-supported" =>
            "O token não foi criado para o protocolo operacional do Worker 4.0.",
        "enrollment-conflict" or "enrollment-challenge-rejected" or "enrollment-rejected" =>
            "O HCH recusou o vínculo ou a prova de posse. Gere um token Worker 4.0 para esta chave do usuário.",
        "enrollment-owner-key-id-invalid" or "enrollment-owner-fingerprint-invalid" or
        "enrollment-proof-owner-key-id-mismatch" or "enrollment-proof-owner-fingerprint-mismatch" =>
            "O token está vinculado a outra chave SSH de proprietário.",
        "enrollment-network-unavailable" or "enrollment-network-timeout" =>
            "O HCH não respondeu. O token não foi salvo; repita com o mesmo token.",
        "ipc-enrollment-identity-unavailable" =>
            "A identidade operacional protegida do Worker ainda não está disponível no serviço.",
        "ipc-enrollment-drain-pending" =>
            "O Worker foi pausado, mas ainda há trabalhos ativos. Aguarde a drenagem antes do enrollment.",
        "ipc-enrollment-protocol-unsupported" =>
            "O serviço instalado não oferece o protocolo de enrollment do Worker 4.0.",
        _ => "O enrollment foi recusado. Código sanitizado: " + code,
    };

    private static void OpenExternal(Uri uri)
    {
        if (uri.Scheme != Uri.UriSchemeHttps
            || !uri.Host.Equals("hah.hubtech.online", StringComparison.OrdinalIgnoreCase)
            || uri.Port != 443
            || !string.IsNullOrEmpty(uri.UserInfo)
            || !string.IsNullOrEmpty(uri.Fragment))
        {
            throw new InvalidOperationException("external-uri-refused");
        }

        _ = Process.Start(new ProcessStartInfo(uri.AbsoluteUri) { UseShellExecute = true });
    }
}
