# filecrypt

A tool to encrypt and decrypt files.

## Example usage

### Symmetric key

#### Encrypting

To encrypt the file *secret.txt*, run the following command:

```shell
filecrypt --file secret.txt
# or shorter:
filecrypt -f secret.txt
```

This will result in 3 files:

1. The encrypted file *secret_encrypted*
2. A key file *secret_encrypted_key.yaml*
3. A metadata file *secret_encrypted_meta.yaml*

The actual data is contained in *secret_encrypted*.
To decrypt *secret_encrypted*, the key contained in *secret_encrypted_key.yaml* is needed.
The file *secret_encrypted_meta.yaml* contains all the other necessary parameters to decrypt the file.

#### Decrypting

In order to decrypt the file *secret_encrypted*, use the following command:

```shell
filecrypt --decrypt --file secret_encrypted
# or shorter:
filecrypt -df secret_encrypted
```

The result is the decrypted file *secret_encrypted_decrypted*.
This command expects the files *secret_encrypted_key.yaml* and *secret_encrypted_meta.yaml* to be present.
If your key file and metadata file have different names, you have to specify them explicitly:

```shell
filecrypt --decrypt --file secret_encrypted --key-file secret_encrypted_key.yaml --metadata-file secret_encrypted_meta.yaml
# or shorter:
filecrypt -df secret_encrypted --key-file secret_encrypted_key.yaml --metadata-file secret_encrypted_meta.yaml
```
