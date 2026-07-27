# The Disk Encryption Lab

## Introduction

### Goal
Set up LUKS disk encryption on a loop device, understand the operational implications and design a backup encryption strategy for MedDefense.

### Context
NAS-01 stores all MedDefense backups in plaintext. If the NAS is stolen, every patient record is exposed. If the NAS is accessed through the flat network (which your 1x01 kill chains demonstrated), the backups are readable. Encrypting the backup storage at rest is a Phase 1 priority from your roadmap.

Before you touch production, you practice on a safe target: a loop device on your own machine.

## Answer

### Part 1
```bash
 dd if=/dev/zero of=encrypted_volume.img bs=1M count=500
500+0 records in
500+0 records out
524288000 bytes (524 MB, 500 MiB) copied, 2.80282 s, 187 MB/s

sudo cryptsetup luksFormat encrypted_volume.img

WARNING!
========
This will overwrite data on encrypted_volume.img irrevocably.

Are you sure? (Type 'yes' in capital letters): YES
Enter passphrase for encrypted_volume.img: 
Verify passphrase:

sudo cryptsetup luksOpen encrypted_volume.img secure_vol
Enter passphrase for encrypted_volume.img: 

sudo mkfs.ext4 /dev/mapper/secure_vol
mke2fs 1.47.4 (6-Mar-2025)
Creating filesystem with 123904 4k blocks and 123904 inodes
Filesystem UUID: 3c4ca296-e3e9-4705-bfd4-13da5f0c3551
Superblock backups stored on blocks: 
        32768, 98304

Allocating group tables: done                            
Writing inode tables: done                            
Creating journal (4096 blocks): done
Writing superblocks and filesystem accounting information: done

sudo mkdir -p /mnt/secure_vol

sudo mount /dev/mapper/secure_vol /mnt/secure_vol

echo "This is a test file for LUKS encryption." | sudo tee /mnt/secure_vol/test.txt
This is a test file for LUKS encryption.

cat /mnt/secure_vol/test.txt
This is a test file for LUKS encryption.

sudo cryptsetup luksClose secure_vol
Device secure_vol is still in use.

sudo umount /mnt/secure_vol

sudo cryptsetup luksClose secure_vol
```

### Part 2
unmount:

```bash
strings encrypted_volume.img | head -50
LUKS
sha256
d0082f42-8f1e-4627-a6f8-3828e98f8cee
W4@X
{"keyslots":{"0":{"type":"luks2","key_size":64,"af":{"type":"luks1","stripes":4000,"hash":"sha256"},"area":{"type":"raw","offset":"32768","size":"258048","encryption":"aes-xts-plain64","key_size":64},"kdf":{"type":"argon2id","time":4,"memory":1048576,"cpus":4,"salt":"cFHBFV603XuvvqVzgrshdMRYc6AUFPiKh66O5SB2nng="}}},"tokens":{},"segments":{"0":{"type":"crypt","offset":"16777216","size":"dynamic","iv_tweak":"0","encryption":"aes-xts-plain64","sector_size":4096}},"digests":{"0":{"type":"pbkdf2","keyslots":["0"],"segments":["0"],"hash":"sha256","iterations":130419,"salt":"839VopM9wjVz8WqB+rDSnWct+dnLWqhLbMAbJzHk9aQ=","digest":"f1qz9cXAcPXuzeystCj5edRAP6ityyEbOJ/8SWnLSvY="}},"config":{"json_size":"12288","keyslots_size":"16744448"}}
SKUL
sha256
{U/v
?}/J
\d0082f42-8f1e-4627-a6f8-3828e98f8cee
{"keyslots":{"0":{"type":"luks2","key_size":64,"af":{"type":"luks1","stripes":4000,"hash":"sha256"},"area":{"type":"raw","offset":"32768","size":"258048","encryption":"aes-xts-plain64","key_size":64},"kdf":{"type":"argon2id","time":4,"memory":1048576,"cpus":4,"salt":"cFHBFV603XuvvqVzgrshdMRYc6AUFPiKh66O5SB2nng="}}},"tokens":{},"segments":{"0":{"type":"crypt","offset":"16777216","size":"dynamic","iv_tweak":"0","encryption":"aes-xts-plain64","sector_size":4096}},"digests":{"0":{"type":"pbkdf2","keyslots":["0"],"segments":["0"],"hash":"sha256","iterations":130419,"salt":"839VopM9wjVz8WqB+rDSnWct+dnLWqhLbMAbJzHk9aQ=","digest":"f1qz9cXAcPXuzeystCj5edRAP6ityyEbOJ/8SWnLSvY="}},"config":{"json_size":"12288","keyslots_size":"16744448"}}
Pjbh]
,%y     .B/s
#kR/
(`vd/D
hqSeO
M,YL
(@@3
5I@{B
of[:D
vx5BQ
aRbu
E"Z6
:vtA
ln8lDM
koL:
[:;L%[&
A5maV}pH
|kdO
-i}U
^I(e
y(\J
smS)
Q1}6
~gVZ
        R>J
8Bp"
R<.X|
i}?lX
-(C-
Wv62
E2|8
%'duI
D8DS<
c1QC
|7A#au
{x4=
svwq
<ZN{M
        [y\
```

mount:
```bash
strings encrypted_volume.img | head -50          
LUKS
sha256
d0082f42-8f1e-4627-a6f8-3828e98f8cee
W4@X
{"keyslots":{"0":{"type":"luks2","key_size":64,"af":{"type":"luks1","stripes":4000,"hash":"sha256"},"area":{"type":"raw","offset":"32768","size":"258048","encryption":"aes-xts-plain64","key_size":64},"kdf":{"type":"argon2id","time":4,"memory":1048576,"cpus":4,"salt":"cFHBFV603XuvvqVzgrshdMRYc6AUFPiKh66O5SB2nng="}}},"tokens":{},"segments":{"0":{"type":"crypt","offset":"16777216","size":"dynamic","iv_tweak":"0","encryption":"aes-xts-plain64","sector_size":4096}},"digests":{"0":{"type":"pbkdf2","keyslots":["0"],"segments":["0"],"hash":"sha256","iterations":130419,"salt":"839VopM9wjVz8WqB+rDSnWct+dnLWqhLbMAbJzHk9aQ=","digest":"f1qz9cXAcPXuzeystCj5edRAP6ityyEbOJ/8SWnLSvY="}},"config":{"json_size":"12288","keyslots_size":"16744448"}}
SKUL
sha256
{U/v
?}/J
\d0082f42-8f1e-4627-a6f8-3828e98f8cee
{"keyslots":{"0":{"type":"luks2","key_size":64,"af":{"type":"luks1","stripes":4000,"hash":"sha256"},"area":{"type":"raw","offset":"32768","size":"258048","encryption":"aes-xts-plain64","key_size":64},"kdf":{"type":"argon2id","time":4,"memory":1048576,"cpus":4,"salt":"cFHBFV603XuvvqVzgrshdMRYc6AUFPiKh66O5SB2nng="}}},"tokens":{},"segments":{"0":{"type":"crypt","offset":"16777216","size":"dynamic","iv_tweak":"0","encryption":"aes-xts-plain64","sector_size":4096}},"digests":{"0":{"type":"pbkdf2","keyslots":["0"],"segments":["0"],"hash":"sha256","iterations":130419,"salt":"839VopM9wjVz8WqB+rDSnWct+dnLWqhLbMAbJzHk9aQ=","digest":"f1qz9cXAcPXuzeystCj5edRAP6ityyEbOJ/8SWnLSvY="}},"config":{"json_size":"12288","keyslots_size":"16744448"}}
Pjbh]
,%y     .B/s
#kR/
(`vd/D
hqSeO
M,YL
(@@3
5I@{B
of[:D
vx5BQ
aRbu
E"Z6
:vtA
ln8lDM
koL:
[:;L%[&
A5maV}pH
|kdO
-i}U
^I(e
y(\J
smS)
Q1}6
~gVZ
        R>J
8Bp"
R<.X|
i}?lX
-(C-
Wv62
E2|8
%'duI
D8DS<
c1QC
|7A#au
{x4=
svwq
<ZN{M
        [y\
```

After closing the LUKS volume, reading `encrypted_volume.img` with `strings` does not reveal the test data because the file contains only encrypted ciphertext, not the original plaintext. This proves that the data is protected **at rest**, meaning an attacker who obtains the encrypted file cannot read the stored information without the LUKS passphrase.

After reopening and mounting the LUKS volume, the data can be read normally because LUKS transparently decrypts the contents when the correct key is provided. The open-mount-read-unmount-close cycle demonstrates that the data remains securely encrypted while stored but is available when authorized access is granted.

### Part 4

For NAS-01, the recommended encryption-at-rest strategy is to use volume-level encryption because it provides a good balance between security and backup performance. Full-disk encryption would protect the entire storage device but may introduce unnecessary overhead for a dedicated backup system, while file-level encryption would require managing encryption individually for each file and may complicate backup operations. A volume encryption approach protects all backup data stored on the NAS while keeping management simpler. Based on the T1 performance measurements, the expected encryption overhead is estimated to be around 5–15% depending on hardware acceleration and workload, which is acceptable for backup storage because security is prioritized over maximum throughput. The encryption key must be stored in a separate secure key management system and NOT on the NAS itself, because storing the key on the same device would allow an attacker who compromises the NAS to access both the encrypted data and the key. If the key is lost, the encrypted backups cannot be recovered, meaning all protected backup data would become permanently inaccessible unless a secure backup copy of the key exists. For offsite backup replication, the cloud replica must also be encrypted because replicated backups may contain the same sensitive recovery data; the cloud replica should be protected using a separate encryption key managed by the organization or a dedicated key management service rather than relying only on the cloud provider’s default encryption key.