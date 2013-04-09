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

namespace Rsft.HttpCookieSecure.Tests.Unit
{
    #region Usings

    using System;
    using System.Web;
    using System.Web.Security;

    using NUnit.Framework;

    #endregion

    /// <summary>
    /// The cookie secure test.
    /// </summary>
    [TestFixture]
    public class CookieSecureTest
    {
        private const string Decrypted = "TestValue";

        private const string CookieName = "MyCookie";

        private HttpCookie testCookie;

        private HttpCookie encodedCookie;

        private CookieProtection cookieProtection;

        #region Public Methods and Operators
        
        /// <summary>
        /// The test fixture setup.
        /// </summary>
        [TestFixtureSetUp]
        public void TestFixtureSetup()
        {
            this.testCookie = new HttpCookie(CookieName, Decrypted);

            this.cookieProtection = CookieProtection.All;
        }

        /// <summary>
        /// The test fixture tear down.
        /// </summary>
        [TestFixtureTearDown]
        public void TestFixtureTearDown()
        {
        }

        /// <summary>
        /// Tests encode method.
        /// </summary>
        /// <remarks>
        /// Encode will produce different hashes on each machine. It is based on MachineKey specified in global or local web.config.
        /// </remarks>
        [Test]
        public void AEncodeTest_UsingMachineKey_ExpectHashedResult()
        {
            // arrange
            
            // act
            this.encodedCookie = CookieSecure.Encode(this.testCookie, this.cookieProtection);

            // assert
            Assert.True(!string.IsNullOrWhiteSpace(this.encodedCookie.Value));
            Console.Write(this.encodedCookie.Value);
        }

        /// <summary>
        /// Tests decode method test.
        /// </summary>
        [Test]
        public void BDecodeTest_UsingPreviouslyEncryptedCookie_ExpectDecryptToKnownValue()
        {
            // arrange
            const string Expected = Decrypted;

            // act
            var httpCookie = CookieSecure.Decode(this.encodedCookie, this.cookieProtection);

            // assert
            StringAssert.AreEqualIgnoringCase(Expected, httpCookie.Value);
            Console.WriteLine(httpCookie.Value);
        }

        #endregion
    }
}