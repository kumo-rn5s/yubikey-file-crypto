# yubikey-file-crypto

Use yubikey to encrypt/decrypt file

Use 24 bit yubikey ManagementKey + 8 bit Pin as AES-256-GCM Key

# Usage

## Setup Pin

```sh
./yubikey-file-crypto -setup 
```

## Encrypt File

```sh
./yubikey-file-crypto -encrypt -filename <filename_to_encrypt>
```

## Decrypt File

```sh
./yubikey-file-crypto -decrypt -filename <encrypted_file.bin>
```