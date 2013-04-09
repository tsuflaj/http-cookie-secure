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
    using System.Text;
    using System.Web.Security;

    using Rsft.HttpCookieSecure.Properties;

    #endregion

    /// <summary>
    /// The machine key cryptography.
    /// </summary>
    internal static class MachineKeyCryptography
    {
        #region Public Methods and Operators

        /// <summary>
        /// Decodes a string and returns null if the string is tampered
        /// </summary>
        /// <param name="text">
        /// String to decode
        /// </param>
        /// <returns>
        /// The decoded string or throws <see cref="CookieSecureException"/> if tampered with
        /// </returns>
        public static string Decode(string text)
        {
            return Decode(text, CookieProtection.All);
        }

        /// <summary>
        /// Decodes a string
        /// </summary>
        /// <param name="text">
        /// String to decode
        /// </param>
        /// <param name="cookieProtection">
        /// The method in which the string is protected
        /// </param>
        /// <returns>
        /// The decoded string or throws <see cref="CookieSecureException"/> if tampered with
        /// </returns>
        public static string Decode(string text, CookieProtection cookieProtection)
        {
            if (string.IsNullOrEmpty(text))
            {
                return text;
            }

            byte[] buf;

            var machineKeyProtection = Map(cookieProtection);

            try
            {
                buf = MachineKey.Decode(text, machineKeyProtection);
            }
            catch (Exception ex)
            {
                throw new CookieSecureException(Resources.CookieError1, ex.InnerException);
            }

            if (buf == null || buf.Length == 0)
            {
                throw new CookieSecureException(Resources.CookieError1);
            }

            return Encoding.UTF8.GetString(buf, 0, buf.Length);
        }

        /// <summary>
        /// Encodes a string and protects it from tampering
        /// </summary>
        /// <param name="text">
        /// String to encode
        /// </param>
        /// <returns>
        /// Encoded string
        /// </returns>
        public static string Encode(string text)
        {
            return Encode(text, CookieProtection.All);
        }

        /// <summary>
        /// Encodes a string
        /// </summary>
        /// <param name="text">
        /// String to encode
        /// </param>
        /// <param name="cookieProtection">
        /// The method in which the string is protected
        /// </param>
        /// <returns>
        /// The <see cref="string"/>.
        /// </returns>
        public static string Encode(string text, CookieProtection cookieProtection)
        {
            if (string.IsNullOrEmpty(text) || cookieProtection == CookieProtection.None)
            {
                return text;
            }

            var buf = Encoding.UTF8.GetBytes(text);

            var map = Map(cookieProtection);

            return MachineKey.Encode(buf, map);
        }

        #endregion

        #region Methods

        /// <summary>
        /// The map.
        /// </summary>
        /// <param name="cookieProtection">
        /// The cookie protection.
        /// </param>
        /// <returns>
        /// The <see cref="MachineKeyProtection"/>.
        /// </returns>
        private static MachineKeyProtection Map(CookieProtection cookieProtection)
        {
            MachineKeyProtection rtn;

            switch (cookieProtection)
            {
                case CookieProtection.Encryption:
                    rtn = MachineKeyProtection.Encryption;
                    break;

                case CookieProtection.Validation:
                    rtn = MachineKeyProtection.Validation;
                    break;

                default:
                    rtn = MachineKeyProtection.All;
                    break;
            }

            return rtn;
        }

        #endregion
    }
}