namespace AxiiProxy;

/// <summary>
///     Proxy server settings.
/// </summary>
public class ProxySettings
{
    public required ProxyType Type { get; init; }
    public required string Host { get; init; } = null!;
    public required int Port { get; init; }
    public string? Username { get; init; }
    public string? Password { get; init; }
}

public enum ProxyType
{
    Http,
    Socks5
}