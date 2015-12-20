using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;

namespace CsEncryption
{
    /// <summary>
    ///     Simple wrapper around <see cref="RijndaelManaged" /> class. Uses 256-bit keys.
    /// </summary>
    public class SimpleAes : IDisposable
    {
        private readonly RijndaelManaged _rijndael;

        /// <summary>
        ///     New <see cref="SimpleAes" /> with known key and IV
        /// </summary>
        /// <param name="key">Key used to encrypt/decrypt</param>
        /// <param name="iv">IV used to encrypt/decrypt. Use null to generate random</param>
        public SimpleAes(byte[] key, byte[] iv)
        {
            _rijndael = new RijndaelManaged();
            Key = key;
            if (iv == null)
            {
                _rijndael.GenerateIV();
            }
            else
            {
                IV = iv;
            }
        }

        /// <summary>
        ///     New <see cref="SimpleAes" /> with random <see cref="Key" /> and <see cref="IV" />
        /// </summary>
        public SimpleAes()
        {
            _rijndael = new RijndaelManaged();
            _rijndael.GenerateIV();
            _rijndael.GenerateKey();
        }

        /// <summary>
        ///     Lenght of <see cref="RijndaelManaged.IV" />. Bytes of this lenght are
        ///     prepended to every encryped string and contain iv itself
        /// </summary>
        public int IVLenght => _rijndael.BlockSize/8;

        /// <summary>
        ///     Key in use
        /// </summary>
        public byte[] Key
        {
            get { return _rijndael?.Key; }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException(nameof(value));
                }
                if (!_rijndael.ValidKeySize(value.Length*8))
                    throw new ArgumentException("Key lenght is invalid!");
                _rijndael.Key = value;
            }
        }

        /// <summary>
        ///     Initialization vector in use
        /// </summary>
        public byte[] IV
        {
            get { return _rijndael?.IV; }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException(nameof(value));
                }
                if (value.Length != IVLenght)
                    throw new ArgumentException("Invalid iv size");
                _rijndael.IV = value;
            }
        }

        /// <summary>
        ///     Block size of Rijndael alg
        /// </summary>
        public int BlockSize => _rijndael.BlockSize;

        /// <summary>
        /// Minimmum lenght to be deciphered
        /// </summary>
        public int MinimmumCipherLenght => BlockSize/8;

        /// <summary>
        ///     Dispose
        /// </summary>
        public void Dispose()
        {
            _rijndael?.Dispose();
        }

        /// <summary>
        ///     Encrypts string to bytes using 256bit Rijndael.
        /// </summary>
        /// <param name="plainText">Text to be encoded</param>
        /// <returns>Cipher in bytes</returns>
        public byte[] Encrypt(string plainText)
        {
            if (plainText == null) throw new ArgumentNullException(nameof(plainText));

            var encryptor = _rijndael.CreateEncryptor();

            // Create the streams used for encryption.
            using (var msEncrypt = new MemoryStream())
            {
                using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (var swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(plainText);
                    }
                    //result of encryption
                    var dec= msEncrypt.ToArray();
                    Debug.WriteLine(dec.Length);
                    Debug.WriteLine(_rijndael.BlockSize);
                    Debug.WriteLine(_rijndael.KeySize);
                    return dec;
                }
            }
        }

        /// <summary>
        ///     Decrypt a cipher made by <see cref="Encrypt" /> with known <see cref="IV" /> and <see cref="Key" />
        /// </summary>
        /// <param name="cipher">Cipher to be decrypted.</param>
        /// <returns>Decrypted string</returns>
        public string Decrypt(byte[] cipher)
        {
            if (cipher == null) throw new ArgumentNullException(nameof(cipher));

            // Create a decrytor to perform the stream transform.
            var decryptor = _rijndael.CreateDecryptor();

            // Create the streams used for decryption.
            try
            {
                using (var msDecrypt = new MemoryStream(cipher))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new StreamReader(csDecrypt))
                        {
                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.

                            return srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            catch (CryptographicException)
            {
                throw new IncorrectPasswordException();
            }
        }
    }
}