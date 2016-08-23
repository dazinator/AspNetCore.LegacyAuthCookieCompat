# AspNetCore.LegacyAuthCookieCompat
This library provides the ability to encrypt or decrypt authentication cookies, that are compatible with .NET 2 & 3.5 web applications, using SHA1 validation and AES.

This is useful if you are hoping to, for example, integrate OWIN / AspNet Core cookies middleware, with the legacy cookie format.

# Usage

In order to encrypt / decrypt the auth cookie data, you need to provide the SHA1 `ValidationKey` and the AES `DecryptionKey`. These can usually be found in your existing asp.net 3.5 websites web.config:

```
    <machineKey validation="SHA1" decryption="AES" validationKey="XXXXX" decryptionKey="XXXXX" />

```

To encrypt a FormsAuthenticationTicket do the following: (We'd usually then write the ecrypted data as an auth cookie)

```csharp
 
          var issueDate = new DateTime(2015, 12, 22, 15, 09, 25);
          var expiryDate = new DateTime(0001, 01, 01, 00, 00, 00);
          var authTicket = new FormsAuthenticationTicket(2, "someuser@some-email.com", issueDate, expiryDate, false, "custom data", "/");

          var sha1Hasher = new Sha1HashProvider(_ValidationKeyText);
          var sut = new LegacyFormsAuthenticationTicketEncryptor(_DecryptionKeyText);

          // Act
          // We encrypt the forms auth cookie.
          var encryptedText = sut.Encrypt(authTicket, sha1Hasher);
          
          // We'd now usually write this as an authentication cookie..

```

To Decrypt: (We'd usually read the encrypted text from the auth cookie)

```csharp
           
            FormsAuthenticationTicket decryptedTicket = sut.DecryptCookie(encryptedText, new Sha1HashProvider(_ValidationKeyText));

```

