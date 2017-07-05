# Seal

Seal is a simple program to encrypt files, notes, and passwords.
Seal depends on the [vis editor](https://github.com/martanne/vis/)
because vis can be used in a pipe without writing temporary files.
Install vis by compiling it from source or using your package manager:

| Distro     | Command to install Vis |
| ---------- | ---------------------- |
| Arch Linux | `pacman -S vis`        |
| Debian     | `apt-get install vis`  |
| OSX        | [Homebrew pull request](https://github.com/Homebrew/homebrew-core/pull/127) |

If you have any ideas on how Seal could use Vim without writing
data in cleartext to disk, let me know!

## First steps

Install Seal and generate your private key:

```
$ go get github.com/davidlazar/seal/...

$ seal-keygen 
Created directory /home/david/.seal
Enter passphrase: 
Enter same passphrase again: 
Wrote public key: /home/david/.seal/david.publickey
Wrote private key: /home/david/.seal/david.privatekey
```

Backup your private key:

```
$ cp ~/.seal/david.privatekey /mnt/usbkey
$ lpr ~/.seal/david.privatekey  # print the private key
```

## Encrypt files

Encrypt a file:

```
$ seal example.pdf
Wrote example.pdf.sealed (encrypted with key david)
$ rm example.pdf
```

Reveal the contents of the encrypted file:

```
$ seal-cat example.pdf.sealed | zathura -
Enter passphrase for key david: ...
```

## Encrypt notes

Seal can create and edit encrypted documents. You do not need to
enter a passphrase to create an encrypted document:

```
$ seal-edit doc.txt.sealed  # launches the vis editor
```

Subsequent edits require a passphrase:

```
$ seal-edit doc.txt.sealed
Enter passphrase for key david: ...
```

## Manage passwords

The `seal-pw` program can be used as a password manager.
To generate a password for a new account:

```
$ seal-pw github  # launches the vis editor to specify account information
```

Run the same command again to copy the password to the clipboard:

```
$ seal-pw github
Enter passphrase for key david: ...
url: github.com
username: davidlazar
Password copied to clipboard for 10 seconds.
```

Use `seal-cat` and `seal-edit` to view and update account information:

```
$ seal-cat github 
Enter passphrase for key david: 
url: github.com
username: davidlazar
clipboard: lQBphTfTTaafOEFCJHc4udEJYvAe99eJ
```