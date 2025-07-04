
# AxiiProxy

---

## English

This solution was created due to the lack of working proxy servers in C# with upstream proxy support and stable operation on Linux.

I tried using [Titanium Web Proxy](https://github.com/justcoding121/titanium-web-proxy), but it behaves unstably on Linux.

### Usage

#### Creating a server without a proxy (proxying through the current IP)

```csharp
await using var proxyServer = new ProxyServer(IPAddress.Loopback, 8888);
```

#### Setting up an upstream proxy (replace with your own data. Authorization is optional.)

```csharp
proxyServer.SetProxy(new ProxySettings
{
    Type = ProxyType.Socks5,
    Host = "127.0.0.1",
    Port = 8888,
    Username = "username",
    Password = "password"
});
```

---

## Русский

Это решение было создано из-за отсутствия рабочих прокси-серверов на C# с поддержкой upstream прокси и стабильной работой в Linux.

Я пытался использовать [Titanium Web Proxy](https://github.com/justcoding121/titanium-web-proxy), но он ведет себя нестабильно на Linux.

### Использование

#### Создание сервера без прокси (проксирование через текущий IP)

```csharp
await using var proxyServer = new ProxyServer(IPAddress.Loopback, 8888);
```

#### Установка upstream прокси (данные нужно заменить на свои. Авторизация опциональна.)

```csharp
proxyServer.SetProxy(new ProxySettings
{
    Type = ProxyType.Socks5,
    Host = "127.0.0.1",
    Port = 8888,
    Username = "username",
    Password = "password"
});
```

---
