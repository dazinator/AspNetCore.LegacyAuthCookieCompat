using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;

namespace AspNetCore.LegacyAuthCookieCompat.Tests
{
    [TestClass]
    public class CookieCompatSHA256Tests
    {
        // web.config : <machineKey validation="HMACSHA256" decryption="AES" ...
        private const string SHA256ValidationKey = "2863C5606B3711FC0857F47664552890E2B060A1C11A0B2221660B3137DB8538164F4813BC5E4AA319F8FE3EB86F3751ADE6A96241664988CBB1C99EAE09E7F4";
        private const string SHA256DecryptionKey = "3C4D2EF2FD5FA7ADA0AE5E7BCC312A31E901AE4821218893";

        [TestMethod]
        public void Can_Decrypt_Forms_Authentication_Ticket_WithSha256()
        {
            // Arrange
            var encryptor = new LegacyFormsAuthenticationTicketEncryptor(SHA256DecryptionKey, SHA256ValidationKey, ShaVersion.Sha256);
            var encryptedText = "71AE29F3588ACE8E0097BA62E71B3E3ADC92FBEAFC2CBBD3FC3AC200EB6F78BC85CE111125F1ED0D7F4A54805F06F572A1D5FAD25A4DE014B54D199E6FBAF10A8674107BD78A310E589A49F2ADF6019785AF065C6677CF769D7CB17419D9BCAC35820862DEBC5894B4012B1406DD5B94248FBF87DA197BBE983A2E0A3068B6FDF83B076E387262534F946E1D861EF008EF7F7B630D7851525F1E883C9D973692";

            // Act            
            FormsAuthenticationTicket result = encryptor.DecryptCookie(encryptedText);

            Assert.AreEqual("/", result.CookiePath);
            Assert.AreEqual(false, result.IsPersistent);
            Assert.AreEqual("foo@bar.com", result.Name);
            Assert.AreEqual("foo@bar.com", result.UserData);
            Assert.AreEqual(1, result.Version);
            Assert.AreEqual(result.IssueDate, new DateTime(636667414570901655, DateTimeKind.Utc).ToLocalTime());
            Assert.AreEqual(result.Expiration, new DateTime(636676054570901655, DateTimeKind.Utc).ToLocalTime());
        }

        [TestMethod]
        public void Can_Encrypt_And_Decrypt_Forms_Authentication_Ticket_WithSha256()
        {
            // Arrange
            var issueDateUtc = DateTime.UtcNow;
            var expiryDateUtc = issueDateUtc.AddHours(1);
            var formsAuthenticationTicket = new FormsAuthenticationTicket(1, "foo@bar.com", issueDateUtc.ToLocalTime(), expiryDateUtc.ToLocalTime(), false, "foo@bar.com", "/");

            var encryptor = new LegacyFormsAuthenticationTicketEncryptor(SHA256DecryptionKey, SHA256ValidationKey, ShaVersion.Sha256);

            // Act            
            var encryptedText = encryptor.Encrypt(formsAuthenticationTicket);

            Assert.IsNotNull(encryptedText);

            // We decrypt the encypted text back into a forms auth ticket, and compare it to the original ticket to make sure it
            // round tripped successfully.
            FormsAuthenticationTicket decryptedFormsAuthenticationTicket = encryptor.DecryptCookie(encryptedText);

            Assert.AreEqual(formsAuthenticationTicket.CookiePath, decryptedFormsAuthenticationTicket.CookiePath);
            Assert.AreEqual(formsAuthenticationTicket.Expiration, decryptedFormsAuthenticationTicket.Expiration);
            Assert.AreEqual(formsAuthenticationTicket.Expired, decryptedFormsAuthenticationTicket.Expired);
            Assert.AreEqual(formsAuthenticationTicket.IsValid(), decryptedFormsAuthenticationTicket.IsValid());
            Assert.AreEqual(formsAuthenticationTicket.IsPersistent, decryptedFormsAuthenticationTicket.IsPersistent);
            Assert.AreEqual(false, decryptedFormsAuthenticationTicket.Expired);
            Assert.AreEqual(true, decryptedFormsAuthenticationTicket.IsValid());
            Assert.AreEqual(formsAuthenticationTicket.IssueDate, decryptedFormsAuthenticationTicket.IssueDate);
            Assert.AreEqual(formsAuthenticationTicket.UserData, decryptedFormsAuthenticationTicket.UserData);
            Assert.AreEqual(formsAuthenticationTicket.Version, decryptedFormsAuthenticationTicket.Version);
        }
    }
}
