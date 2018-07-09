[![Build status](https://ci.appveyor.com/api/projects/status/sbsp39sva2i7d5ks/branch/master?svg=true)](https://ci.appveyor.com/project/dazinator/aspnetcore-legacyauthcookiecompat/branch/master)

# AspNetCore.LegacyAuthCookieCompat
This library provides the ability to encrypt or decrypt a `FormsAuthenticationTicket` which are used for Forms Authentication cookies.
The cookie will be compatible with .NET 2 / 3.5 & .NET 4 asp.net web applications, that use FormsAuthentication, with SHA1, SHA256, SHA512 validations and AES.

This is useful if you are hoping to, for example, integrate OWIN / AspNet Core cookies middleware, with a legacy .NET 3.5 web application, and want single sign on / off.

# Usage

In order to encrypt / decrypt the auth cookie data, you need to provide the `ValidationKey` and `DecryptionKey`. These can usually be found in your existing asp.net 3.5 websites web.config.

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

var legacyFormsAuthenticationTicketEncryptor = new LegacyFormsAuthenticationTicketEncryptor(decryptionKeyBytes, validationKeyBytes, ShaVersion.Sha1);

// Act
// We encrypt the forms auth cookie.
var encryptedText = legacyFormsAuthenticationTicketEncryptor.Encrypt(formsAuthenticationTicket);
```

To Decrypt: (We'd usually read the encrypted text from the auth cookie)

```csharp
FormsAuthenticationTicket decryptedTicket = legacyFormsAuthenticationTicketEncryptor.DecryptCookie(encryptedText);
```

