using System.Security.Cryptography;

namespace AES_Encryption_App
{
    public partial class Form1 : Form
    {

      //Egehan Cinarli - 641716 -> I have used the microsoft documentation for creating this assignment
      //which is (Walkthrough: Create a Cryptographic Application)
        private string EncryptionFolder = Directory.GetParent(Environment.CurrentDirectory).Parent.Parent.FullName + @"\EncryptFolder\";
        private string DecryptionFolder = Directory.GetParent(Environment.CurrentDirectory).Parent.Parent.FullName + @"\DecryptFolder\";
        private string SrcFolder = @"c:\docs\";


        // Key container name for
        // private/public key value pair.
        const string KeyName = "key";

        readonly CspParameters _cspp = new CspParameters();
        RSACryptoServiceProvider _rsa;


        public Form1()
        {
            InitializeComponent();
            InitPath();
           
        }
        private void InitPath()
        {
            FileEncryptBox.InitialDirectory = EncryptionFolder;
            FileDecryptBox.InitialDirectory = DecryptionFolder;
            CreateASMKey();
        }



        //Encryption with AES
        private void button1_Click(object sender, EventArgs e)
        {
            //No need to check if rsa is null here since it is being set in the init method.
            if (FileEncryptBox.ShowDialog() == DialogResult.OK)
                {
                    string fName = FileEncryptBox.FileName;
                    if (fName != null)
                    {
                        // Pass the file name without the path.
                        EncryptFile(new FileInfo(fName));
                    }
                }
            
        }
        private void EncryptFile(FileInfo file)
        {
            
            Aes aes = Aes.Create();
            ICryptoTransform transform = aes.CreateEncryptor();

         
            byte[] keyEncrypted = _rsa.Encrypt(aes.Key, false);
            int lKey = keyEncrypted.Length;
            byte[] LenK = BitConverter.GetBytes(lKey);
            int lIV = aes.IV.Length;
            byte[] LenIV = BitConverter.GetBytes(lIV);

            
            string outFile =
                Path.Combine(DecryptionFolder, Path.ChangeExtension(file.Name, ".enc"));

            using (var outFs = new FileStream(outFile, FileMode.Create))
            {
                outFs.Write(LenK, 0, 4);
                outFs.Write(LenIV, 0, 4);
                outFs.Write(keyEncrypted, 0, lKey);
                outFs.Write(aes.IV, 0, lIV);

                using (var outStreamEncrypted =
                    new CryptoStream(outFs, transform, CryptoStreamMode.Write))
                {
                    int count = 0;
                    int offset = 0;

                    
                    int blockSizeBytes = aes.BlockSize / 8;
                    byte[] data = new byte[blockSizeBytes];
                    int bytesRead = 0;

                    using (var inFs = new FileStream(file.FullName, FileMode.Open))
                    {
                        do
                        {
                            count = inFs.Read(data, 0, blockSizeBytes);
                            offset += count;
                            outStreamEncrypted.Write(data, 0, count);
                            bytesRead += blockSizeBytes;
                        } while (count > 0);
                    }
                    outStreamEncrypted.FlushFinalBlock();
                }
            }
        }
        private void CreateASMKey()
        {
            _cspp.KeyContainerName = KeyName;
            _rsa = new RSACryptoServiceProvider(_cspp)
            {
                PersistKeyInCsp = true
            };
        }
        //Decryption with AES
        private void button2_Click(object sender, EventArgs e)
        {
                //No need to check if rsa is null here since it is being set in the init method.
                // Display a dialog box to select the encrypted file.
                if (FileDecryptBox.ShowDialog() == DialogResult.OK)
                {
                    string fName = FileDecryptBox.FileName;
                    if (fName != null)
                    {
                        DecryptFile(new FileInfo(fName));
                    }
                }
            
            
        }
        private void DecryptFile(FileInfo file)
        {

            Aes aes = Aes.Create();

            
            byte[] LenK = new byte[4];
            byte[] LenIV = new byte[4];

           

            string outFile =
                Path.ChangeExtension(file.FullName.Replace("FileEncrypt","FileDecrypt"), ".txt");

          
            using (var inFs = new FileStream(file.FullName, FileMode.Open))
            {
                inFs.Seek(0, SeekOrigin.Begin);
                inFs.Read(LenK, 0, 3);
                inFs.Seek(4, SeekOrigin.Begin);
                inFs.Read(LenIV, 0, 3);

      
                int lenK = BitConverter.ToInt32(LenK, 0);
                int lenIV = BitConverter.ToInt32(LenIV, 0);

             
                int startC = lenK + lenIV + 8;
                int lenC = (int)inFs.Length - startC;

            
                byte[] KeyEncrypted = new byte[lenK];
                byte[] IV = new byte[lenIV];

              
                inFs.Seek(8, SeekOrigin.Begin);
                inFs.Read(KeyEncrypted, 0, lenK);
                inFs.Seek(8 + lenK, SeekOrigin.Begin);
                inFs.Read(IV, 0, lenIV);

                Directory.CreateDirectory(DecryptionFolder);
               
                byte[] KeyDecrypted = _rsa.Decrypt(KeyEncrypted, false);

               
                ICryptoTransform transform = aes.CreateDecryptor(KeyDecrypted, IV);

              
                using (var outFs = new FileStream(outFile, FileMode.Create))
                {
                    int count = 0;
                    int offset = 0;

                  
                    int blockSizeBytes = aes.BlockSize / 8;
                    byte[] data = new byte[blockSizeBytes];

                  

                  
                    inFs.Seek(startC, SeekOrigin.Begin);
                    using (var outStreamDecrypted =
                        new CryptoStream(outFs, transform, CryptoStreamMode.Write))
                    {
                        do
                        {
                            count = inFs.Read(data, 0, blockSizeBytes);
                            offset += count;
                            outStreamDecrypted.Write(data, 0, count);
                        } while (count > 0);

                        outStreamDecrypted.FlushFinalBlock();
                    }
                }
            }
        }

        private void Form1_Load(object sender, EventArgs e)
        {

        }
    }
}