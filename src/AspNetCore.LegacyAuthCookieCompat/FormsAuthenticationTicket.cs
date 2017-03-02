using System;

namespace AspNetCore.LegacyAuthCookieCompat
{
	public sealed class FormsAuthenticationTicket
	{
		public int Version { get; private set; }
		public string Name { get; private set; }
		public DateTime IssueDate { get; private set; }
		public DateTime Expiration { get; private set; }
		public bool IsPersistent { get; private set; }
		public string UserData { get; private set; }
		public string CookiePath { get; private set; }

		public bool Expired { get { return DateTime.Now >= Expiration; } }

		public FormsAuthenticationTicket(int version, string name, DateTime issueDate, DateTime expiration, bool isPersistent, string userData, string cookiePath)
		{
			Version = version;
			Name = name;
			IssueDate = issueDate;
			Expiration = expiration;
			IsPersistent = isPersistent;
			UserData = userData;
			CookiePath = cookiePath;
		}
	}
}