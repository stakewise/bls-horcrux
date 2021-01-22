# BLS Horcrux

## Introduction

`bls-horcrux` is a tool for creating a threshold BLS key in a trustless manner. It
uses [Shamir's secret sharing](https://launchpad.ethereum.org/faq#keys)
and [BLS properties](https://blog.dash.org/secret-sharing-and-threshold-signatures-with-bls-954d1587b5f) to create a key
that is shared between `m` parties and requires `n out of m` signatures to reconstruct the final signature.

## Installation

### Prerequisites

- [Python **3.8+**](https://www.python.org/about/gettingstarted/)
- [pip3](https://pip.pypa.io/en/stable/installing/)

### Option 1. Build `bls-horcrux` with native Python

```shell script
pip3 install -r requirements/prod.txt
```

Or use the helper script:

```shell script
./horcrux.sh install
```

### Option 2. Build `bls-horcrux` with `virtualenv`

For the [virtualenv](https://virtualenv.pypa.io/en/latest/) users, you can create a new `venv`:

```shell script
python3 -m venv venv
source venv/bin/activate
```

and install the dependencies:

```shell script
pip install -r requirements/prod.txt
```

### Option 3. Build the docker image

Run the following command locally to build the docker image:

```shell script
docker build --pull -t bls-horcrux .
```

## Preparation

### Common

Before BLS horcruxes can be generated, their holders must agree on the following:

- **Participants** - who are the holders of the horcruxes and how many there will be in total.
- **Threshold** - the minimum number of BLS signatures required to reconstruct the final signature.
- **Dispatcher** - what endpoint should be used for the horcruxes to
  communicate ([See dispatcher](./dispatcher/README.md)).
- **Offline PC** - a PC which is isolated from the Internet, where the final horcrux will be generated.
- **Online PC** - a PC which connected to the Internet and is used for interacting with the dispatcher.

### Individual

Choose how would you like to execute the commands required to generate your horcrux:

- Shell script (the examples below will be given using this method):
    ```shell script
    ./horcrux.sh <command>
    ```
- Python:
    ```shell script
    python3 horcrux.py <command>
    ```
- Docker:
    ```shell script
    docker run -it --rm -v $(pwd)/data:/app/data bls-horcrux <command>
    ```

## Creating horcrux

To create the BLS horcrux every participant must execute the following command and follow the steps after:

```shell script
  linux-gnu
  Running BLS horcrux...
  Enter path to the file where the RSA private key should be saved [/bls-horcrux/data/rsa_key.pem]: 
  Generating RSA key for communicating with other horcruxes...
  
  
  ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQClQeqE71JrB2x8JI4iNNxeIFBIuM2NSxjtX6zdh0fsYTJwOqhQVQdC97Zvjux2gPsei1e7wCSPbK96QQBYL4ieojFmbIUQWhHBVsyG62fscNiwK4bgfzIBTioKiehs9/ipj47XGVPs0jf6HreeFl5DkCap60j1dRG7AGJo5lxSP2/0PYJ3YqRvR8d9u8lugomU6QnB0UHNJhrwOmnI0NZCWu0AmGg9+8hW5KKJbeID3T1L3L0axIKvoiw+y7fnMQi1hkKUJa/D8JcwveJY77Wg3hPhDayKgf5xgDbvCDHm/PslzOqZaa3rjUzo4UZJ+jrxsAzP4YBDKN3yQcLDo7E2Nwj/sEsnB/D775loh+e7d4MDP9fbj3SzAsLhtwUliK116/5ErPzNAPozI8ZuzK41wR4xerTcqnsLBJHJXbCPFqQw3iWnNNiwota1/QxtXHHckzg/pKBPjZqgO04QqxdhLYYv1p1/vT+C48ajv/+0Ax3j+8Ifp6BKafrl/ZAvKJhmrOX8/ntM3SKd9krGKI5ORvr59NJVk4jMylH784m1iij9YRI5gWRd9pXl889cTJTrgijqi+T/8jT7G+W7xBiB4zFFBLCy88K4NdiAxuhSnnzD0sLOOSpK+GDUUCs9c8rwaHLp4nn5NnTX9zJwfZwTOAIWGTaP4b+ffDQIMn2U7w==
  
  
  Enter the password that secures your RSA key: 
  Repeat for confirmation: 
  Saved RSA private key to /bls-horcrux/data/rsa_key.pem
  Next steps:
  1) Share the RSA public key above with all other participants.
  2) Paste yours and other participants' RSA public keys to
     /bls-horcrux/data/all_rsa_public_keys.txt file.
     NB! The file must be equal for all the participants.
  3) Run ./horcrux.sh create-bls-key on your offline PC.
```

## Signing data

To sign a message, call the command below and pass all the required parameters:

```shell script
   ./horcrux.sh sign --horcrux-file /bls-horcrux/data/horcrux0.json
   linux-gnu
   Running BLS horcrux...
   Enter the horcrux password used during your horcrux creation: 
   Enter hexadecimal encoded data to sign: 0x48656c6c6f20576f726c6421
   Signature: 0x91f5c9ce5cee0b1953649fe5f57672d295f654ec7930e2d7bbafed03df5bfadd42a75a5bbf977b0ed17af05244f72063017257cd31d0f9f16409fa188f2dad784821bbc7e507b70c20c97630abf52d781a812f4edfd317b1b1220abc2fdd491b
   Horcrux index: 0
   Next steps:
   1) Retrieve signatures of the same signing data from other horcruxes.
   2) Run ./horcrux.sh reconstruct-signature to reconstruct the final signature.
      NB! At least 3 signatures are required to reconstruct.
```

## Reconstructing threshold signature

To reconstruct a final signature, collect signatures and indexes from other horcruxes (as in the section above) and
call:

 ```shell script
  ./horcrux.sh reconstruct-signature
  darwin19
  Running BLS horcrux...
  Enter the total number of BLS signatures to reconstruct the final signature from: 3
  Enter the horcrux index of the submitted signature (can be found in the owner's horcrux file): 0
  Enter the next hexadecimal encoded BLS signature (1/3): 0x88dbee76bca22f82f56bd846f3b2844975191b87dc9cd9fa1823a5fa33607eb188d8dcb4d46e06c69358a7e407c1f3a40c9cece031e8f45259c9731b5e24a32704ef60781a3de1663e2a12a136c9de54e5202f72dc8783afa3180d33258a5528
  Enter the horcrux index of the submitted signature (can be found in the owner's horcrux file): 3
  Enter the next hexadecimal encoded BLS signature (2/3): 0xa1da37d002e282837198ecad02ffc8b5aaf9ecf5260b04659d8544383defbf6b7518a9ca06f1d0ece6c84935e50816cf0211867e681e3a179db26b3c28a14c1ea25983a703a0e06fac336b29d7e88e98414edbd736bd83b0d9b68c99201aab87
  Enter the horcrux index of the submitted signature (can be found in the owner's horcrux file): 1
  Enter the next hexadecimal encoded BLS signature (3/3): 0x80e9b13f5a81e678d797b59c76e70c1d8bc385a6d253917a651a7738487a7ab8bd70f6246e8adfeb0f22a35eb4f6eab61474c7f6d73bf68456f4fe04ce9055e302de86cd3186993ac86c77dacc38ed3d648c57d602f903071253439e7cff158b
  Reconstructed signature: 0xad9c32db5ba78df50b058c4b659ec1f708e1c6f821c163e1dc60a9e54dcb7f575d44083c8de3dda188fe7a2c9c641a7c00b11136c6dc1cbd6a851d1087e88d18c0b5a59229073e885dde8358e44459c68c8b8bfdaf5e60853238451ce7264d4d
  Run ./horcrux.sh verify-signature to verify whether the signature is correct.
 ```

**NB!** Number of signatures should be at least equal to the amount specified in `threshold` from `step 1`
of `Creating Horcrux` section. The data signed must be the same for all the participants.

## Verifying threshold signature

To verify the signature, copy the value of the shared BLS public key (`shared_public_key`) from the horcrux keystore and
call:

```shell script
  ./horcrux.sh verify-signature
  darwin19
  Running BLS horcrux...
  Enter the hexadecimal encoded shared BLS public key to verify (can be found in horcrux file): 95dbbf215b9fd18c797f309b95f6eff5756c0e8edf474adfff0358ac25cdcff3aacae8d8e51dc4807a1cd8e99c053c57
  Enter the hexadecimal encoded signing data: 0x48656c6c6f20576f726c6421
  Enter the hexadecimal encoded BLS signature to verify: 0xad9c32db5ba78df50b058c4b659ec1f708e1c6f821c163e1dc60a9e54dcb7f575d44083c8de3dda188fe7a2c9c641a7c00b11136c6dc1cbd6a851d1087e88d18c0b5a59229073e885dde8358e44459c68c8b8bfdaf5e60853238451ce7264d4d
  [+] The signature is valid
```
