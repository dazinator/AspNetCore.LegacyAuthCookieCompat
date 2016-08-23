using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web.Security;
using NUnit.Framework;

namespace AspNetCore.LegacyAuthCookieCompat.Tests
{


    [TestFixture]
    public class CookieCompatTests
    {
        // These would come from the asp.net 3.5 applications web.config.
        // I have made thes eup for the purposes of this test.
        private string _ValidationKeyText = "30101052676849B0B494466B7A99656346328E8964748448E422D7344467A45777D972414947271744423422851D6742C9A09A65212C276C7F839157501291C6";
        private string _DecryptionKeyText = "AC7387D7E54B156377D81930CF237888854B5B5B515CF2D6356541255E696144";

       
        [Test]
        public void Can_Encrypt_And_Decrypt_Forms_Authentication_Ticket()
        {
           
            // Arrange
            var issueDate = new DateTime(2015, 12, 22, 15, 09, 25);
            var expiryDate = new DateTime(0001, 01, 01, 00, 00, 00);
            var authTicket = new FormsAuthenticationTicket(2, "someuser@some-email.com", issueDate, expiryDate, false, "custom data", "/");

            var sha1Hasher = new Sha1HashProvider(_ValidationKeyText);
            var sut = new LegacyFormsAuthenticationTicketEncryptor(_DecryptionKeyText);

            // Act
            // We encrypt the forms auth cookie.
            var encryptedText = sut.Encrypt(authTicket, sha1Hasher);
            
            Assert.NotNull(encryptedText);
            Console.Write(encryptedText);

            // We decrypt the encypted text back into a forms auth ticket, and compare it to the original ticket to make sure it
            // roundtripped successfully.
            FormsAuthenticationTicket decryptedTicket = sut.DecryptCookie(encryptedText, new Sha1HashProvider(_ValidationKeyText));

            Assert.That(() => authTicket.CookiePath, Is.EqualTo(decryptedTicket.CookiePath));
            Assert.That(() => authTicket.Expiration, Is.EqualTo(decryptedTicket.Expiration));
            Assert.That(() => authTicket.Expired, Is.EqualTo(decryptedTicket.Expired));
            Assert.That(() => authTicket.IsPersistent, Is.EqualTo(decryptedTicket.IsPersistent));
            Assert.That(() => authTicket.IssueDate, Is.EqualTo(decryptedTicket.IssueDate));
            Assert.That(() => authTicket.UserData, Is.EqualTo(decryptedTicket.UserData));
            Assert.That(() => authTicket.Version, Is.EqualTo(decryptedTicket.Version));

        }
    }

}
