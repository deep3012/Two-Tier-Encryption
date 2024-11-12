This project aims to enhance the security of data stored in databases by combining two wellestablished encryption algorithms—AES (Advanced Encryption Standard) and ChaCha—along with the use of SHA-256 for hashing the stored values. The primary objective is to ensure
that even during an attack, the data remains secure through robust encryption.
As a proof of concept, cryptanalysis will be employed to assess the security strength of the implemented solution, ensuring its reliability under potential attack scenarios. The combination of AES and ChaCha is preferred over other
algorithms due to their complementary nature and the diverse security they provide against a range of potential vulnerabilities.


Output:
The system produces a SHA-256 hash as the final output after encrypting the plaintext through AES and ChaCha20. This hash represents the encrypted data and can be used for further integrity checks or storage. Due to the nature of the hash
function, the original plaintext cannot be retrieved directly from the hash but can be verified by comparing it to a newly generated hash from the same plaintext.
