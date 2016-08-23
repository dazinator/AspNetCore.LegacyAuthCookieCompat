This library provides a class called LegacyFormsAuthenticationTicketEncryptor that can be used 
in web applications to decrypt .NET 2 / 3.5 based FormsAuthentication cookies. This library was born
out of the need to decrypt the a .net 3.5 authentation cookie, from an ASP.NET 5 / Core
web application so could have single sign on accross the 2 sites. ASP.NET 5 / Core doesn't provide
anything out of the box to decrypt these .NET based legacy cookies, and there only seems to be compat
documentation for asp.net 4 sites and onwards, so this library was written.