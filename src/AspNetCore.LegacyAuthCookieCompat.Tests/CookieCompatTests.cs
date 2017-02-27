using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace AspNetCore.LegacyAuthCookieCompat.Tests
{
	[TestClass]
    public class CookieCompatTests
    {
        // These would come from the asp.net 3.5 applications web.config.
        // I have made thes eup for the purposes of this test.
        private string _ValidationKeyText = "30101052676849B0B494466B7A99656346328E8964748448E422D7344467A45777D972414947271744423422851D6742C9A09A65212C276C7F839157501291C6";
        private string _DecryptionKeyText = "AC7387D7E54B156377D81930CF237888854B5B5B515CF2D6356541255E696144";

       
        [TestMethod]
        public void Can_Encrypt_And_Decrypt_Forms_Authentication_Ticket()
        {
           
            // Arrange
            var issueDate = new DateTime(2015, 12, 22, 15, 09, 25);
            var expiryDate = new DateTime(2018, 01, 01, 00, 00, 00);
            var formsAuthenticationTicket = new FormsAuthenticationTicket(2, "someuser@some-email.com", issueDate, expiryDate, false, "custom data", "/");
			
            var legacyFormsAuthenticationTicketEncryptor = new LegacyFormsAuthenticationTicketEncryptor(_DecryptionKeyText, _ValidationKeyText);

			// Act
			// We encrypt the forms auth cookie.
			byte[] validationKeyBytes = HexUtils.HexToBinary(_ValidationKeyText);
			var sha1Hasher = new Sha1HashProvider(validationKeyBytes);
			var encryptedText = legacyFormsAuthenticationTicketEncryptor.Encrypt(formsAuthenticationTicket, sha1Hasher);
            
            Assert.IsNotNull(encryptedText);
            Console.Write(encryptedText);

            // We decrypt the encypted text back into a forms auth ticket, and compare it to the original ticket to make sure it
            // roundtripped successfully.
            FormsAuthenticationTicket decryptedFormsAuthenticationTicket = legacyFormsAuthenticationTicketEncryptor.DecryptCookie(encryptedText);

			Assert.AreEqual(formsAuthenticationTicket.CookiePath, decryptedFormsAuthenticationTicket.CookiePath);
			Assert.AreEqual(formsAuthenticationTicket.Expiration, decryptedFormsAuthenticationTicket.Expiration);
			Assert.AreEqual(formsAuthenticationTicket.Expired, decryptedFormsAuthenticationTicket.Expired);
			Assert.AreEqual(formsAuthenticationTicket.IsPersistent, decryptedFormsAuthenticationTicket.IsPersistent);
			Assert.AreEqual(formsAuthenticationTicket.IssueDate, decryptedFormsAuthenticationTicket.IssueDate);
			Assert.AreEqual(formsAuthenticationTicket.UserData, decryptedFormsAuthenticationTicket.UserData);
			Assert.AreEqual(formsAuthenticationTicket.Version, decryptedFormsAuthenticationTicket.Version);
		}
    }

}
