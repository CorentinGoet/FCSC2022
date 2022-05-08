# Echec OP 0/3

Categories: intro, forensics

## Challenge
For this challenge, we have to find the unique identifier (UUID) of
a partition table.
The disk file is too big to be added to GitHub.

## Write-up
To start this challenge, download and unzip the file.
To find the UUID of the partition table, we can use the _blkid_ tool
on Linux:
```shell
blkid fcsc.raw
```

We get the result:
```text
fcsc.raw: PTUUID="60da4a85-6f6f-4043-8a38-0ab83853e6dc" PTTYPE="gpt"
```