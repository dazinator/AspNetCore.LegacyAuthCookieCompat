[![Build status](https://ci.appveyor.com/api/projects/status/sbsp39sva2i7d5ks/branch/master?svg=true)](https://ci.appveyor.com/project/dazinator/aspnetcore-legacyauthcookiecompat/branch/master)

[![NuGet](https://img.shields.io/nuget/v/AspNetCore.LegacyAuthCookieCompat.svg)](https://www.nuget.org/packages/AspNetCore.LegacyAuthCookieCompat/)

# AspNetCore.LegacyAuthCookieCompat
This library provides the ability to encrypt or decrypt a `FormsAuthenticationTicket` which are used for Forms Authentication cookies.
The cookie will be compatible with ASP.NET 4.5 and lower web applications, that use FormsAuthentication, with SHA1, SHA256, SHA512 validations and AES.
Both Framework20SP2 (ASP.NET 2.0 to 4.0 compatibility) and Framework45 (ASP.NET 4.5) compatibility modes are available.

This is useful if you are hoping to, for example, integrate OWIN / AspNet Core cookies middleware, with a legacy .NET 4.5 (or lower) web application, and want single sign on / off.

# Usage

In order to encrypt / decrypt the auth cookie data, you need to provide the `ValidationKey` and `DecryptionKey`. These can usually be found in your existing asp.net websites web.config.

Web.config with SHA1 should like like below:

```
    <machineKey validation="SHA1" validationKey="XXXXX" decryption="AES" decryptionKey="XXXXX" />

```

Web.config with SHA256 should like like below:

```
    <machineKey validation="HMACSHA256" validationKey="XXXXX" decryption="AES" decryptionKey="XXXXX" />

```

Web.config with SHA512 should like like below:
```
    <machineKey validation="HMACSHA512" validationKey="XXXXX" decryption="AES" decryptionKey="XXXXX" />

```

Then, within your application that wishes to read the cookie (or produce one) - add the following NuGet package:

https://www.nuget.org/packages/AspNetCore.LegacyAuthCookieCompat/

To encrypt a FormsAuthenticationTicket do the following: (We'd usually then write the encrypted data as an auth cookie)

```csharp
string validationKey = "30101052676849B0B494466B7A99656346328E8964748448E422D7344467A45777D972414947271744423422851D6742C9A09A65212C276C7F839157501291C6";
string decryptionKey = "AC7387D7E54B156377D81930CF237888854B5B5B515CF2D6356541255E696144";

// Arrange
var issueDate = DateTime.Now;
var expiryDate = issueDate.AddHours(1);
var formsAuthenticationTicket = new FormsAuthenticationTicket(2, "someuser@some-email.com", issueDate, expiryDate, false, "custom data", "/");

byte[] decryptionKeyBytes = HexUtils.HexToBinary(decryptionKey);
byte[] validationKeyBytes = HexUtils.HexToBinary(validationKey);

// Default compatibility mode is Framework20SP2. This supports ASP.NET 2.0 applications as well as higher version with compatibilityMode="Framework20SP1" on the machineKey config.
var legacyFormsAuthenticationTicketEncryptor = new LegacyFormsAuthenticationTicketEncryptor(decryptionKeyBytes, validationKeyBytes, ShaVersion.Sha1);
// For ASP.NET 4.5 applications without compatibilityMode="Framework20SP1", use Framework45 compatibility mode
// var legacyFormsAuthenticationTicketEncryptor = new LegacyFormsAuthenticationTicketEncryptor(decryptionKeyBytes, validationKeyBytes, ShaVersion.Sha1, CompatibilityMode.Framework45);

// Act
// We encrypt the forms auth cookie.
var encryptedText = legacyFormsAuthenticationTicketEncryptor.Encrypt(formsAuthenticationTicket);
```

To Decrypt: (We'd usually read the encrypted text from the auth cookie)

```csharp
FormsAuthenticationTicket decryptedTicket = legacyFormsAuthenticationTicketEncryptor.DecryptCookie(encryptedText);
```

