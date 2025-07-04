using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging;

namespace AxiiProxy;

public class ProxyServer : IAsyncDisposable
{
    private static readonly HashSet<string> HttpMethods = new(StringComparer.OrdinalIgnoreCase)
    {
        "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"
    };

    private static ILogger<ProxyServer>? _logger;
    private readonly string? _authPassword;
    private readonly string? _authUsername;
    private readonly CancellationToken _cancellationToken;
    private readonly CancellationTokenSource _cancellationTokenSource;
    private readonly TcpListener _listener;

    private ProxySettings? _proxySettings;

    public ProxyServer(IPAddress address, int port, string? authUsername = null, string? authPassword = null,
        CancellationToken cancellationToken = default)
    {
        _authUsername = authUsername;
        _authPassword = authPassword;
        _cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _cancellationToken = _cancellationTokenSource.Token;
        _listener = new TcpListener(address, port);
        _listener.Start();
        _logger?.LogInformation("Proxy server started on port {ListenerLocalEndpoint}...", _listener.LocalEndpoint);
        Task.Run(async () =>
        {
            while (!_cancellationToken.IsCancellationRequested)
                try
                {
                    var client = await _listener.AcceptTcpClientAsync();
                    _ = HandleClientAsync(client);
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "Error accepting client");
                }
        }, _cancellationToken);
    }

    public async ValueTask DisposeAsync()
    {
        await _cancellationTokenSource.CancelAsync();
        _listener.Stop();
        _listener.Server.Close();
        _logger?.LogInformation("Proxy server stopped.");
        GC.SuppressFinalize(this);
    }

    public static void SetLogger(ILogger<ProxyServer> logger)
    {
        _logger = logger;
    }

    public void SetProxy(ProxySettings settings)
    {
        _proxySettings = settings;
    }


    private static async Task<Socket> ConnectViaSocks5Async(string proxyHost, int proxyPort, string proxyUser,
        string proxyPass, string? destHost, int destPort)
    {
        var proxy = new IPEndPoint((await Dns.GetHostAddressesAsync(proxyHost))[0], proxyPort);
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync(proxy);

        // 1. Greeting username/password auth
        byte[] greeting = [0x05, 0x01, 0x02]; // SOCKS5, 1 method, username/password
        await socket.SendAsync(greeting, SocketFlags.None);

        var method = new byte[2];
        await socket.ReceiveAsync(method, SocketFlags.None);
        if (method[1] != 0x02) throw new Exception("SOCKS5 proxy does not support username/password auth");

        // 2. Username/Password auth
        var userBytes = Encoding.ASCII.GetBytes(proxyUser);
        var passBytes = Encoding.ASCII.GetBytes(proxyPass);
        var auth = new byte[3 + userBytes.Length + passBytes.Length];
        auth[0] = 0x01;
        auth[1] = (byte)userBytes.Length;
        Array.Copy(userBytes, 0, auth, 2, userBytes.Length);
        auth[2 + userBytes.Length] = (byte)passBytes.Length;
        Array.Copy(passBytes, 0, auth, 3 + userBytes.Length, passBytes.Length);
        await socket.SendAsync(auth, SocketFlags.None);

        var authResp = new byte[2];
        await socket.ReceiveAsync(authResp, SocketFlags.None);
        if (authResp[1] != 0x00) throw new Exception("SOCKS5 authentication failed");

        // 3. CONNECT command
        var destAddr = Encoding.ASCII.GetBytes(destHost ?? throw new Exception("Destination host is null"));
        var connectReq = new byte[7 + destAddr.Length];
        connectReq[0] = 0x05; // SOCKS5
        connectReq[1] = 0x01; // CONNECT
        connectReq[2] = 0x00; // Reserved
        connectReq[3] = 0x03; // Domain
        connectReq[4] = (byte)destAddr.Length;
        Array.Copy(destAddr, 0, connectReq, 5, destAddr.Length);
        connectReq[5 + destAddr.Length] = (byte)(destPort >> 8);
        connectReq[6 + destAddr.Length] = (byte)(destPort & 0xFF);
        await socket.SendAsync(connectReq, SocketFlags.None);

        var resp = new byte[10];
        await socket.ReceiveAsync(resp, SocketFlags.None);
        if (resp[1] != 0x00) throw new Exception("SOCKS5 connect failed");

        return socket;
    }

    private static async Task<Socket> ConnectViaHttpProxyAsync(string proxyHost, int proxyPort, string? proxyUser,
        string? proxyPass, string? destHost, int destPort)
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync(proxyHost, proxyPort);
        var stream = new NetworkStream(socket, false);
        var connectLine = $"CONNECT {destHost}:{destPort} HTTP/1.1\r\n";
        var headers = connectLine + $"Host: {destHost}:{destPort}\r\n";
        if (!string.IsNullOrEmpty(proxyUser) && !string.IsNullOrEmpty(proxyPass))
        {
            var auth = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{proxyUser}:{proxyPass}"));
            headers += $"Proxy-Authorization: Basic {auth}\r\n";
        }

        headers += "\r\n";
        var reqBytes = Encoding.ASCII.GetBytes(headers);
        await stream.WriteAsync(reqBytes);
        var respBuffer = new byte[4096];
        var read = await stream.ReadAsync(respBuffer);
        var resp = Encoding.ASCII.GetString(respBuffer, 0, read);
        if (!resp.Contains("200"))
            throw new Exception("HTTP proxy CONNECT failed: " + resp);
        return socket;
    }

    private async Task<Socket> ConnectToDestinationAsync(string? destHost, int destPort)
    {
        var proxy = _proxySettings;
        switch (proxy?.Type)
        {
            case ProxyType.Socks5 when !string.IsNullOrEmpty(proxy.Host):
                // SOCKS5
                return await ConnectViaSocks5Async(proxy.Host, proxy.Port, proxy.Username ?? "", proxy.Password ?? "",
                    destHost, destPort);
            case ProxyType.Http when !string.IsNullOrEmpty(proxy.Host):
                // HTTP-прокси
                return await ConnectViaHttpProxyAsync(proxy.Host, proxy.Port, proxy.Username, proxy.Password, destHost,
                    destPort);
            default:
            {
                // Прямое соединение
                var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                await socket.ConnectAsync(destHost ?? throw new Exception("Destination host is null"), destPort,
                    _cancellationToken);
                return socket;
            }
        }
    }

    private bool CheckClientAuthorization(string? requestHeader)
    {
        if (string.IsNullOrEmpty(_authUsername) || string.IsNullOrEmpty(_authPassword))
            return true; // авторизация не требуется
        if (string.IsNullOrEmpty(requestHeader))
            return false;
        var lines = requestHeader.Split("\r\n");
        foreach (var line in lines)
        {
            if (!line.StartsWith("Proxy-Authorization: Basic ", StringComparison.OrdinalIgnoreCase)) continue;
            var encoded = line["Proxy-Authorization: Basic ".Length..].Trim();
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
            var parts = decoded.Split(':');
            if (parts.Length == 2 && parts[0] == _authUsername && parts[1] == _authPassword)
                return true;
        }

        return false;
    }

    private (string destHost, int destPort, bool isHttpConnect) ParseRequestHeader(string requestHeader)
    {
        if (requestHeader.StartsWith("CONNECT "))
        {
            var line = requestHeader.Split('\n')[0];
            var parts = line.Split(' ');
            var hostPort = parts[1].Split(':');
            return (hostPort[0], int.Parse(hostPort[1]), true);
        }

        if (HttpMethods.Contains(requestHeader.Split(' ')[0]))
        {
            var line = requestHeader.Split('\n')[0];
            var tokens = line.Split(' ');
            var url = tokens[1];
            var uri = new Uri(url);
            return (uri.Host, uri.Port == -1 ? 80 : uri.Port, false);
        }

        var firstLine = requestHeader.Split('\n')[0].Trim();
        if (firstLine.Contains(':'))
        {
            var hp = firstLine.Split(':');
            return (hp[0], int.Parse(hp[1]), false);
        }

        throw new Exception("Invalid request header");
    }

    private async Task ForwardRequestAsync(NetworkStream clientStream, NetworkStream serverStream, string requestHeader,
        byte[] buffer, int bytesRead, bool isHttpConnect)
    {
        if (isHttpConnect)
        {
            await clientStream.WriteAsync("HTTP/1.1 200 Connection Established\r\n\r\n"u8.ToArray(),
                _cancellationToken);
        }
        else if (HttpMethods.Contains(requestHeader.Split(' ')[0]))
        {
            var lines = requestHeader.Split("\r\n");
            var method = lines[0].Split(' ')[0];
            var uri = new Uri(lines[0].Split(' ')[1]);
            lines[0] = $"{method} {uri.PathAndQuery} HTTP/1.1";
            var newHeader = string.Join("\r\n", lines) + "\r\n\r\n";
            var newRequest = Encoding.ASCII.GetBytes(newHeader);
            await serverStream.WriteAsync(newRequest, _cancellationToken);
        }
        else
        {
            await serverStream.WriteAsync(buffer.AsMemory(0, bytesRead), _cancellationToken);
        }
    }

    /// <summary>
    ///     Handles the client (asynchronously)
    /// </summary>
    private async Task HandleClientAsync(TcpClient client)
    {
        await using var clientStream = client.GetStream();
        var buffer = new byte[8192];
        var bytesRead = await clientStream.ReadAsync(buffer, _cancellationToken);
        if (bytesRead == 0) return;

        var requestHeader = Encoding.ASCII.GetString(buffer, 0, bytesRead);
        if (!CheckClientAuthorization(requestHeader))
        {
            var resp =
                "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Proxy\"\r\nContent-Length: 0\r\n\r\n";
            await clientStream.WriteAsync(Encoding.ASCII.GetBytes(resp), _cancellationToken);
            client.Close();
            return;
        }

        string destHost;
        int destPort;
        bool isHttpConnect;
        try
        {
            (destHost, destPort, isHttpConnect) = ParseRequestHeader(requestHeader);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Error parsing request header");
            client.Close();
            return;
        }

        try
        {
            var serverSocket = await ConnectToDestinationAsync(destHost, destPort);
            await using var serverStream = new NetworkStream(serverSocket, true);
            await ForwardRequestAsync(clientStream, serverStream, requestHeader, buffer, bytesRead, isHttpConnect);
            var clientToServer = clientStream.CopyToAsync(serverStream, _cancellationToken);
            var serverToClient = serverStream.CopyToAsync(clientStream, _cancellationToken);
            await Task.WhenAny(clientToServer, serverToClient);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Error while handling client");
            client.Close();
        }
    }
}