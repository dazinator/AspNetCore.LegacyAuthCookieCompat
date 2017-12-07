using System;
using System.Diagnostics;
using System.IO;

namespace AspNetCore.LegacyAuthCookieCompat
{
	internal static class FormsAuthenticationTicketHelper
	{
		private const byte CURRENT_TICKET_SERIALIZED_VERSION = 0x01;
		private const int MAX_TICKET_LENGTH = 4096;

		/// <summary>
		/// Resurrects a FormsAuthenticationTicket from its serialized blob representation.
		/// The input blob must be unsigned and unencrypted. This function returns null if
		/// the serialized ticket format is invalid. The caller must also verify that the
		/// ticket is still valid, as this method doesn't check expiration.
		/// </summary>
		/// <param name="serializedTicket"></param>
		/// <param name="serializedTicketLength"></param>
		/// <returns></returns>
		public static FormsAuthenticationTicket Deserialize(byte[] serializedTicket, int serializedTicketLength)
		{
			try
			{
				using (MemoryStream ticketBlobStream = new MemoryStream(serializedTicket))
				{
					using (SerializingBinaryReader ticketReader = new SerializingBinaryReader(ticketBlobStream))
					{

						// Step 1: Read the serialized format version number from the stream.
						// Currently the only supported format is 0x01.
						// LENGTH: 1 byte
						byte serializedFormatVersion = ticketReader.ReadByte();
						if (serializedFormatVersion != CURRENT_TICKET_SERIALIZED_VERSION)
						{
							return null; // unexpected value
						}

						// Step 2: Read the ticket version number from the stream.
						// LENGTH: 1 byte
						int ticketVersion = ticketReader.ReadByte();

						// Step 3: Read the ticket issue date from the stream.
						// LENGTH: 8 bytes
						long ticketIssueDateUtcTicks = ticketReader.ReadInt64();
						DateTime ticketIssueDateUtc = new DateTime(ticketIssueDateUtcTicks, DateTimeKind.Utc);
						DateTime ticketIssueDateLocal = ticketIssueDateUtc.ToLocalTime();

						// Step 4: Read the spacer from the stream.
						// LENGTH: 1 byte
						byte spacer = ticketReader.ReadByte();
						if (spacer != 0xfe)
						{
							return null; // unexpected value
						}

						// Step 5: Read the ticket expiration date from the stream.
						// LENGTH: 8 bytes
						long ticketExpirationDateUtcTicks = ticketReader.ReadInt64();
						DateTime ticketExpirationDateUtc = new DateTime(ticketExpirationDateUtcTicks, DateTimeKind.Utc);
						DateTime ticketExpirationDateLocal = ticketExpirationDateUtc.ToLocalTime();

						// Step 6: Read the ticket persistence field from the stream.
						// LENGTH: 1 byte
						byte ticketPersistenceFieldValue = ticketReader.ReadByte();
						bool ticketIsPersistent;
						switch (ticketPersistenceFieldValue)
						{
							case 0:
								ticketIsPersistent = false;
								break;
							case 1:
								ticketIsPersistent = true;
								break;
							default:
								return null; // unexpected value
						}

						// Step 7: Read the ticket username from the stream.
						// LENGTH: 1+ bytes (7-bit encoded integer char count + UTF-16LE payload)
						string ticketName = ticketReader.ReadBinaryString();

						// Step 8: Read the ticket custom data from the stream.
						// LENGTH: 1+ bytes (7-bit encoded integer char count + UTF-16LE payload)
						string ticketUserData = ticketReader.ReadBinaryString();

						// Step 9: Read the ticket cookie path from the stream.
						// LENGTH: 1+ bytes (7-bit encoded integer char count + UTF-16LE payload)
						string ticketCookiePath = ticketReader.ReadBinaryString();

						// Step 10: Read the footer from the stream.
						// LENGTH: 1 byte
						byte footer = ticketReader.ReadByte();
						if (footer != 0xff)
						{
							return null; // unexpected value
						}

						// Step 11: Verify that we have consumed the entire payload.
						// We don't expect there to be any more information after the footer.
						// The caller is responsible for telling us when the actual payload
						// is finished, as he may have handed us a byte array that contains
						// the payload plus signature as an optimization, and we don't want
						// to misinterpet the signature as a continuation of the payload.
						if (ticketBlobStream.Position != serializedTicketLength)
						{
							return null;
						}

						// Success.
						return FromUtc(
							ticketVersion /* version */,
							ticketName /* name */,
							ticketIssueDateUtc /* issueDateUtc */,
							ticketExpirationDateUtc /* expirationUtc */,
							ticketIsPersistent /* isPersistent */,
							ticketUserData /* userData */,
							ticketCookiePath /* cookiePath */);
					}
				}
			}
			catch
			{
				// If anything goes wrong while parsing the token, just treat the token as invalid.
				return null;
			}
		}

		internal static FormsAuthenticationTicket FromUtc(int version, String name, DateTime issueDateUtc, DateTime expirationUtc, bool isPersistent, String userData, String cookiePath)
		{
			FormsAuthenticationTicket ticket = new FormsAuthenticationTicket(version, name, issueDateUtc, expirationUtc, isPersistent, userData, cookiePath);


			//ticket._IssueDateUtcHasValue = true;
			//ticket._IssueDateUtc = issueDateUtc;
			//ticket._ExpirationUtcHasValue = true;
			//ticket._ExpirationUtc = expirationUtc;

			return ticket;
		}

		/// <summary>
		/// Turns a FormsAuthenticationTicket into a serialized blob.
		/// The resulting blob is not encrypted or signed.
		/// </summary>
		/// <param name="ticket"></param>
		/// <returns></returns>
		public static byte[] Serialize(FormsAuthenticationTicket ticket)
		{
			using (MemoryStream ticketBlobStream = new MemoryStream())
			{
				using (SerializingBinaryWriter ticketWriter = new SerializingBinaryWriter(ticketBlobStream))
				{

					// SECURITY NOTE:
					// Earlier versions of the serializer (Framework20 / Framework40) wrote out a
					// random 8-byte header as the first part of the payload. This random header
					// was used as an IV when the ticket was encrypted, since the early encryption
					// routines didn't automatically append an IV when encrypting data. However,
					// the MSRC 10405 (Pythia) patch causes all of our crypto routines to use an
					// IV automatically, so there's no need for us to include a random IV in the
					// serialized stream any longer. We can just write out only the data, and the
					// crypto routines will do the right thing.

					// Step 1: Write the ticket serialized format version number (currently 0x01) to the stream.
					// LENGTH: 1 byte
					ticketWriter.Write(CURRENT_TICKET_SERIALIZED_VERSION);

					// Step 2: Write the ticket version number to the stream.
					// This is the developer-specified FormsAuthenticationTicket.Version property,
					// which is just ticket metadata. Technically it should be stored as a 32-bit
					// integer instead of just a byte, but we have historically been storing it
					// as just a single byte forever and nobody has complained.
					// LENGTH: 1 byte
					ticketWriter.Write((byte)ticket.Version);

					// Step 3: Write the ticket issue date to the stream.
					// We store this value as UTC ticks. We can't use DateTime.ToBinary() since it
					// isn't compatible with .NET v1.1.
					// LENGTH: 8 bytes (64-bit little-endian in payload)
					ticketWriter.Write(ticket.IssueDate.ToUniversalTime().Ticks);

					// Step 4: Write a one-byte spacer (0xfe) to the stream.
					// One of the old ticket formats (Framework40) expects the unencrypted payload
					// to contain 0x000000 (3 null bytes) beginning at position 9 in the stream.
					// Since we're currently at offset 10 in the serialized stream, we can take
					// this opportunity to purposely inject a non-null byte at this offset, which
					// intentionally breaks compatibility with Framework40 mode.
					// LENGTH: 1 byte
					Debug.Assert(ticketBlobStream.Position == 10, "Critical that we be at position 10 in the stream at this point.");
					ticketWriter.Write((byte)0xfe);

					// Step 5: Write the ticket expiration date to the stream.
					// We store this value as UTC ticks.
					// LENGTH: 8 bytes (64-bit little endian in payload)
					ticketWriter.Write(ticket.Expiration.ToUniversalTime().Ticks);

					// Step 6: Write the ticket persistence field to the stream.
					// LENGTH: 1 byte
					ticketWriter.Write(ticket.IsPersistent);

					// Step 7: Write the ticket username to the stream.
					// LENGTH: 1+ bytes (7-bit encoded integer char count + UTF-16LE payload)
					ticketWriter.WriteBinaryString(ticket.Name);

					// Step 8: Write the ticket custom data to the stream.
					// LENGTH: 1+ bytes (7-bit encoded integer char count + UTF-16LE payload)
					ticketWriter.WriteBinaryString(ticket.UserData);

					// Step 9: Write the ticket cookie path to the stream.
					// LENGTH: 1+ bytes (7-bit encoded integer char count + UTF-16LE payload)
					ticketWriter.WriteBinaryString(ticket.CookiePath);

					// Step 10: Write a one-byte footer (0xff) to the stream.
					// One of the old FormsAuthenticationTicket formats (Framework20) requires
					// that the payload end in 0x0000 (U+0000). By making the very last byte
					// of this format non-null, we can guarantee a compatiblity break between
					// this format and Framework20.
					// LENGTH: 1 byte
					ticketWriter.Write((byte)0xff);

					// Finished.
					return ticketBlobStream.ToArray();
				}
			}
		}

		public static byte[] SerialiseLegacy(FormsAuthenticationTicket ticket, bool encrypt, bool legacyPadding)
		{
			throw new NotImplementedException("Commented out, check wheter this is still used, and if there is a native way of doing it");

			//byte[] bData = new byte[4096]; // will store the ticket data.

			//byte[] pBin = new byte[4];

			//long[] pDates = new long[2];
			//byte[] pNull = { 0, 0, 0 };

			//// DevDiv Bugs 137864: 8 bytes may not be enough random bits as the length should be equal to the
			//// key size. In CompatMode > Framework20SP1, use the IVType.Random feature instead of these 8 bytes,
			//// but still include empty 8 bytes for compat with webengine.dll, where CookieAuthConstructTicket is.
			//// Note that even in CompatMode = Framework20SP2 we fill 8 bytes with random data if the ticket
			//// is not going to be encrypted.

			//bool willEncrypt = encrypt;
			//// bool legacyPadding = !willEncrypt || (MachineKeySection.CompatMode == MachineKeyCompatibilityMode.Framework20SP1);
			//if (legacyPadding)
			//{
			//	// Fill the first 8 bytes of the blob with random bits
			//	byte[] bRandom = new byte[8];
			//	RandomNumberGenerator randgen = RandomNumberGenerator.Create();
			//	randgen.GetBytes(bRandom);
			//	Buffer.BlockCopy(bRandom, 0, bData, 0, 8);
			//}
			//else
			//{
			//	// use blank 8 bytes for compatibility with CookieAuthConstructTicket (do nothing)
			//}

			//pBin[0] = (byte)ticket.Version;
			//pBin[1] = (byte)(ticket.IsPersistent ? 1 : 0);

			//pDates[0] = ticket.IssueDate.ToFileTime();
			//pDates[1] = ticket.Expiration.ToFileTime();

			//int iRet = UnsafeNativeMethods.CookieAuthConstructTicket(
			//			bData, bData.Length,
			//			ticket.Name, ticket.UserData, ticket.CookiePath,
			//			pBin, pDates);

			//if (iRet < 0)
			//	return null;

			//byte[] ciphertext = new byte[iRet];
			//Buffer.BlockCopy(bData, 0, ciphertext, 0, iRet);
			//return ciphertext;

		}

		public static FormsAuthenticationTicket DeserialiseLegacy(byte[] serializedTicket, int serializedTicketLength)
		{
			throw new NotImplementedException("Commented out, check wheter this is still used, and if there is a native way of doing it");

			//int iSize = ((serializedTicketLength > MAX_TICKET_LENGTH) ? MAX_TICKET_LENGTH : serializedTicketLength);
			//StringBuilder name = new StringBuilder(iSize);
			//StringBuilder data = new StringBuilder(iSize);
			//StringBuilder path = new StringBuilder(iSize);
			//byte[] pBin = new byte[4];
			//long[] pDates = new long[2];

			//int iRet = UnsafeNativeMethods.CookieAuthParseTicket(serializedTicket, serializedTicketLength,
			//													   name, iSize,
			//													   data, iSize,
			//													   path, iSize,
			//													   pBin, pDates);

			//if (iRet != 0)
			//	return null;

			//DateTime dt1 = DateTime.FromFileTime(pDates[0]);
			//DateTime dt2 = DateTime.FromFileTime(pDates[1]);

			//FormsAuthenticationTicket ticket = new FormsAuthenticationTicket((int)pBin[0],
			//										 name.ToString(),
			//										 dt1,
			//										 dt2,
			//										 (bool)(pBin[1] != 0),
			//										 data.ToString(),
			//										 path.ToString());
			//return ticket;
		}

		// see comments on SerializingBinaryWriter
		private sealed class SerializingBinaryReader : BinaryReader
		{
			public SerializingBinaryReader(Stream input)
				: base(input)
			{
			}

			public string ReadBinaryString()
			{
				int charCount = Read7BitEncodedInt();
				byte[] bytes = ReadBytes(charCount * 2);

				char[] chars = new char[charCount];
				for (int i = 0; i < chars.Length; i++)
				{
					chars[i] = (char)(bytes[2 * i] | (bytes[2 * i + 1] << 8));
				}

				return new String(chars);
			}

			public override string ReadString()
			{
				// should never call this method since it will produce wrong results
				throw new NotImplementedException();
			}
		}

		/// <summary>
		/// This is a special BinaryWriter which serializes strings in a way that is
		/// entirely round-trippable. For example, the string "\ud800" is a valid .NET
		/// Framework string, but since U+D800 is an unpaired Unicode surrogate the
		/// built-in Encoding types will not round-trip it. Strings are serialized as a
		/// 7-bit character count (not byte count!) followed by a UTF-16LE payload.
		/// </summary>
		private sealed class SerializingBinaryWriter : BinaryWriter
		{
			public SerializingBinaryWriter(Stream output)
				: base(output)
			{
			}

			public override void Write(string value)
			{
				// should never call this method since it will produce wrong results
				throw new NotImplementedException();
			}

			public void WriteBinaryString(string value)
			{
				byte[] bytes = new byte[value.Length * 2];
				for (int i = 0; i < value.Length; i++)
				{
					char c = value[i];
					bytes[2 * i] = (byte)c;
					bytes[2 * i + 1] = (byte)(c >> 8);
				}

				Write7BitEncodedInt(value.Length);
				Write(bytes);
			}
		}

	}



}
