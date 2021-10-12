# yubikey-file-crypto

Use yubikey to encrypt/decrypt file

File Encypt/Decrypt use AES-256-GCM Key

# Usage

## Setup Pin

```sh
yubikey-file-crypto -setup 
```

## Reset Pin

```sh
yubikey-file-crypto -setup -reset
```

## Encrypt File

```sh
yubikey-file-crypto -encrypt -filename <filename_to_encrypt>
```

## Decrypt File

```sh
yubikey-file-crypto -decrypt -filename <encrypted_file.bin>
```
