# filecrypt

A tool to encrypt and decrypt files.

## Example usage

### Symmetric key

#### Encrypting

To encrypt the file *secret.txt*, run the following command:

```shell
filecrypt encrypt secret.txt
# or shorter:
filecrypt e secret.txt
```

This will result in 3 files:

1. The encrypted file *secret_enc*
2. A key file *secret_enc_key*
3. A metadata file *secret_enc.toml*

The actual data is contained in *secret_enc*.
To decrypt *secret_enc*, the key contained in *secret_enc_key* is needed.
The file *secret_enc.toml* contains all the other necessary parameters to decrypt the file.

#### Decrypting

In order to decrypt the file *secret_enc*, use the following command:

```shell
filecrypt decrypt secret_enc
# or shorter:
filecrypt d secret_enc
```

The result is the decrypted file *secret_enc_dec*.
This command expects the files *secret_enc_key* and *secret_enc.toml* to be present.
If your key file and metadata file have different names, you have to specify them explicitly:

```shell
filecrypt --key-file secret_enc_key --metadata-file secret_enc.toml decrypt secret_enc
# or shorter:
filecrypt -k secret_enc_key -m secret_enc.toml d secret_enc
```
