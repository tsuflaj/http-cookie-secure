namespace Rsft.HttpCookieSecure
{
    #region Usings

    using System;
    using System.Runtime.Serialization;

    #endregion

    /// <summary>
    /// The cookie secure exception.
    /// </summary>
    [Serializable]
    public class CookieSecureException : Exception
    {
        // For guidelines regarding the creation of new exception types, see
        // http://msdn.microsoft.com/library/default.asp?url=/library/en-us/cpgenref/html/cpconerrorraisinghandlingguidelines.asp
        // and
        // http://msdn.microsoft.com/library/default.asp?url=/library/en-us/dncscol/html/csharp07192001.asp
        #region Constructors and Destructors

        /// <summary>
        /// Initializes a new instance of the <see cref="CookieSecureException"/> class.
        /// </summary>
        public CookieSecureException()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CookieSecureException"/> class.
        /// </summary>
        /// <param name="message">
        /// The message.
        /// </param>
        public CookieSecureException(string message)
            : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CookieSecureException"/> class.
        /// </summary>
        /// <param name="message">
        /// The message.
        /// </param>
        /// <param name="inner">
        /// The inner.
        /// </param>
        public CookieSecureException(string message, Exception inner)
            : base(message, inner)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CookieSecureException"/> class.
        /// </summary>
        /// <param name="info">
        /// The info.
        /// </param>
        /// <param name="context">
        /// The context.
        /// </param>
        protected CookieSecureException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }

        #endregion
    }
}