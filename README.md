# filecrypt

A tool to encrypt and decrypt files.

```shell
filecrypt --help
```

## Symmetric key

### Encrypting

To encrypt the file *secret.txt*, run the following command:

```shell
filecrypt secret.txt
```

This will result in 3 files:

1. The encrypted file *secret.txt.bin*
2. A key file *secret.txt.bin.key.yaml*
3. A metadata file *secret.txt.bin.meta.yaml*

The actual data is contained in *secret.txt.bin*.
To decrypt *secret.txt.bin*, the key contained in *secret.txt.bin.key.yaml* is needed.
The file *secret.txt.bin.meta.yaml* contains all the other necessary parameters to decrypt the file.

### Decrypting

In order to decrypt the file *secret.txt.bin*, use the following command:

```shell
filecrypt secret.txt.bin --decrypt
```

The result is the decrypted file *decrypted_secret.txt*.
This command expects the files *secret.txt.bin.key.yaml* and *secret.txt.bin.meta.yaml* to be present.
If your key file and metadata file have different names, you have to specify them explicitly:

```shell
filecrypt
secret.txt.bin
--decrypt
--key-file=secret.txt.bin.key.yaml
--metadata=secret.txt.bin.meta.yaml
```

## Password based

### Encrypting

To encrypt *secret.txt* using a password, run the following command:

```shell
filecrypt secret.txt --password
```

You will be asked for a password which you need to enter.
If you want to specify the password via the command line arguments,
that is possible as well:

```shell
filecrypt secret.txt --password=supersecret
```

### Decrypting

To decrypt the resulting *secret.txt.bin*, you need to enter the password again.

```shell
filecrypt secret.txt --decrypt --password
```

## Verifying file contents

If you want to verify that a file has not been corrupted, use the `--verification` option when encrypting.

```shell
filecrypt secret.txt --verification
```

As long as you keep the metadata file, the file contents will be verified automatically on decryption.

```shell
filecrypt secret.txt --decrypt
```

## Signing file contents

If you want to sign the file contents, use the `--signature` option when encrypting.

```shell
filecrypt secret.txt --signature
```

As long as you keep the metadata file, the signature will be verified automatically on decryption.

```shell
filecrypt secret.txt --decrypt
```
