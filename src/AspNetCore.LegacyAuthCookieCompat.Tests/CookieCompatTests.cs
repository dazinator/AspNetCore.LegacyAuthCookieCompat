using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace AspNetCore.LegacyAuthCookieCompat.Tests
{
	[TestClass]
	public class CookieCompatTests
	{
		[TestMethod]
		public void Can_Encrypt_And_Decrypt_Forms_Authentication_Ticket()
		{
			// These would come from the asp.net 3.5 applications <machineKey decryption="AES" decryptionKey"" validation="SHA1" validationKey="" /> web.config.
			// I have made these up for the purposes of this test.
			string _ValidationKeyText = "30101052676849B0B494466B7A99656346328E8964748448E422D7344467A45777D972414947271744423422851D6742C9A09A65212C276C7F839157501291C6";
			string _DecryptionKeyText = "AC7387D7E54B156377D81930CF237888854B5B5B515CF2D6356541255E696144";

			// Arrange
			var issueDate = DateTime.Now;
			var expiryDate = issueDate.AddHours(1);
			var formsAuthenticationTicket = new FormsAuthenticationTicket(2, "someuser@some-email.com", issueDate, expiryDate, false, "custom data", "/");

			byte[] decryptionKeyBytes = HexUtils.HexToBinary(_DecryptionKeyText);
			byte[] validationKeyBytes = HexUtils.HexToBinary(_ValidationKeyText);

			var legacyFormsAuthenticationTicketEncryptor = new LegacyFormsAuthenticationTicketEncryptor(decryptionKeyBytes, validationKeyBytes);

			// Act
			// We encrypt the forms auth cookie.
			var encryptedText = legacyFormsAuthenticationTicketEncryptor.Encrypt(formsAuthenticationTicket);

			Assert.IsNotNull(encryptedText);

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
