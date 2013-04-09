/*
Copyright 2013 Rolosoft.com

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

namespace Rsft.HttpCookieSecure
{
    #region Usings

    using System;
    using System.Web;
    using System.Web.Security;

    using Rsft.HttpCookieSecure.Properties;

    #endregion

    /// <summary>
    ///     <para>
    ///         <c>CookieSecure</c> provides secure cookie encryption and decryption services.
    ///     </para>
    /// </summary>
    /// <remarks>
    ///     <para> This module provides tamper proof encryrption and decryption of standard HTTP Cookies. </para>
    ///     <para>
    ///         <c>CookieSecure</c> uses the same internal encryption modules as
    ///         <see
    ///             cref="System.Web.Security.FormsAuthentication" />
    ///         .
    ///     </para>
    ///     <para>
    ///         This component can be used in web farms. To enable web farm support, please ensure that you set the same <c>machineKey</c> attribute in Web.config.
    ///     </para>
    /// </remarks>
    public static class CookieSecure
    {
        #region Public Methods and Operators

        /// <summary>
        /// The decode.
        /// </summary>
        /// <param name="cookie">
        /// The cookie.
        /// </param>
        /// <returns>
        /// The <see cref="HttpCookie"/>.
        /// </returns>
        public static HttpCookie Decode(HttpCookie cookie)
        {
            return Decode(cookie, CookieProtection.All);
        }

        /// <summary>
        /// Decodes a cookie from definable protection level.
        /// </summary>
        /// <param name="cookie">
        /// The encoded cookie to decode of type <see cref="System.Web.HttpCookie"/> .
        /// </param>
        /// <param name="cookieProtection">
        /// An enumeration of type <see cref="System.Web.Security.CookieProtection"/> defining the level of protection to use when decoding the cookie.
        /// </param>
        /// <returns>
        /// An object of type <see cref="System.Web.HttpCookie"/> which is the decoded cookie.
        /// </returns>
        /// <exception cref="CookieSecureException">
        /// Thrown if
        ///     <paramref name="cookie"/>
        ///     is invalid or tampered.
        /// </exception>
        /// <example>
        /// The following C# example shows how to decode a cookie that has been encoded using "Encryption" only.
        ///     <code>
        /// HttpCookie standardCookie = Request.Cookies["MyCookieName"];
        ///     if(standardCookie!=null)
        ///     {
        ///     HttpCookie decodedCookie = CookieSecure.Decode(standardCookie,System.Web.Security.CookieProtection.Encryption);
        ///     //...Go on to process decoded cookie
        ///     }
        /// </code>
        /// </example>
        public static HttpCookie Decode(HttpCookie cookie, CookieProtection cookieProtection)
        {
            if (cookie != null)
            {
                var decodedCookie = CloneCookie(cookie);
                decodedCookie.Value = MachineKeyCryptography.Decode(cookie.Value, cookieProtection);
                return decodedCookie;
            }

            return null;
        }

        /// <summary>
        /// Encodes a cookie with All protection levels
        /// </summary>
        /// <param name="cookie">
        /// An object of type <see cref="System.Web.HttpCookie"/> to encode.
        /// </param>
        /// <returns>
        /// An object of type <see cref="System.Web.HttpCookie"/> encoded and tamper proof.
        /// </returns>
        /// <exception cref="CookieSecureException">
        /// Thrown if
        ///     <paramref name="cookie"/>
        ///     is invalid or tamper is detected.
        /// </exception>
        /// <example>
        /// The following C# example demonstrates how to Encode a cookie.
        ///     <code>
        /// //Create a value to store
        ///     string myValueToStoreInCookie = "My details";
        /// 
        ///     //Create a "standard" (unencrypted) HttpCookie
        ///     HttpCookie myCookie = new HttpCookie("MyCookieName",myValueToStoreInCookie);
        /// 
        ///     //encrypt the "standard" cookie
        ///     HttpCookie myEncodedCookie = CookieSecure.Encode(myCookie);
        /// 
        ///     //Add the encoded cookie to the response stream.
        ///     Page.Response.AppendCookie(myEncodedCookie);
        /// </code>
        /// </example>
        public static HttpCookie Encode(HttpCookie cookie)
        {
            return Encode(cookie, CookieProtection.All);
        }

        /// <summary>
        /// Encodes a cookie with definable protection levels.
        /// </summary>
        /// <param name="cookie">
        /// An object of type <see cref="System.Web.HttpCookie"/> to encode.
        /// </param>
        /// <param name="cookieProtection">
        /// An enumeration of type <see cref="System.Web.Security.CookieProtection"/> defining the level of protection required.
        /// </param>
        /// <returns>
        /// An object of type <see cref="System.Web.HttpCookie"/> encoded and tamper proof.
        /// </returns>
        /// <exception cref="CookieSecureException">
        /// Thrown if
        ///     <paramref name="cookie"/>
        ///     is invalid or tamper is detected.
        /// </exception>
        /// <example>
        /// The following C# example demonstrates how to Encode a cookie.
        ///     <code>
        /// //Create a value to store
        ///     string myValueToStoreInCookie = "My details";
        /// 
        ///     //Create a "standard" (unencrypted) HttpCookie
        ///     HttpCookie myCookie = new HttpCookie("MyCookieName",myValueToStoreInCookie);
        /// 
        ///     //encrypt the "standard" cookie
        ///     HttpCookie myEncodedCookie = CookieSecure.Encode(myCookie, System.Web.Security.CookieProtection.Encryption);
        /// 
        ///     //Add the encoded cookie to the response stream.
        ///     Page.Response.AppendCookie(myEncodedCookie);
        /// </code>
        /// </example>
        public static HttpCookie Encode(HttpCookie cookie, CookieProtection cookieProtection)
        {
            try
            {
                if (cookie != null)
                {
                    var encodedCookie = CloneCookie(cookie);
                    encodedCookie.Value = MachineKeyCryptography.Encode(cookie.Value, cookieProtection);
                    return encodedCookie;
                }

                return null;
            }
            catch (Exception ex)
            {
                throw new CookieSecureException(Resources.CookieError2, ex.InnerException);
            }
        }

        #endregion

        #region Methods

        /// <summary>
        /// Creates a clone of the given cookie
        /// </summary>
        /// <param name="cookie">
        /// A cookie to clone.
        /// </param>
        /// <returns>
        /// The cloned cookie.
        /// </returns>
        private static HttpCookie CloneCookie(HttpCookie cookie)
        {
            if (cookie != null)
            {
                var clonedCookie = new HttpCookie(cookie.Name, cookie.Value)
                                       {
                                           Domain = cookie.Domain, 
                                           Expires = cookie.Expires, 
                                           HttpOnly = cookie.HttpOnly, 
                                           Path = cookie.Path, 
                                           Secure = cookie.Secure
                                       };
                return clonedCookie;
            }

            return null;
        }

        #endregion
    }
}