

Server side software for IIS.

## Features ##
  * encryption and decryption of HTTP cookies.
  * provides protection against manual cookie tampering.

Compatible with .NET 4.0 / 4.5 frameworks.

## Example usage ##

### Encode ###
```c#

string myValueToStoreInCookie = "My details";

/*Create a "standard" (unencrypted) HttpCookie*/
HttpCookie myCookie = new HttpCookie("MyCookieName",myValueToStoreInCookie);

/*encrypt the "standard" cookie*/
HttpCookie myEncodedCookie = CookieSecure.Encode(myCookie);

/*Add the encoded cookie to the response stream.*/
Page.Response.AppendCookie(myEncodedCookie);
```

### Decode ###
```c#

HttpCookie standardCookie = Request.Cookies["MyCookieName"];
if(standardCookie!=null)
{
HttpCookie decodedCookie = CookieSecure.Decode(standardCookie,System.Web.Security.CookieProtection.Encryption);
/*...Go on to process decoded cookie*/
}
```

## Signing And QA ##
Unit and integration tests are included in the source code where appropriate.
Assemblies are signed and ready for use in your signed or unsigned .NET projects.

## Download ##
https://nuget.org/packages/Rsft.HttpCookieSecure/