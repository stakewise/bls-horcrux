# BLS Horcrux

## Introduction

`bls-horcrux` is a tool for creating a threshold BLS key in a trustless manner. It
uses [Shamir's secret sharing](https://launchpad.ethereum.org/faq#keys)
and [BLS properties](https://blog.dash.org/secret-sharing-and-threshold-signatures-with-bls-954d1587b5f) to create a key
which is shared between `m` parties and requires `n out of m` signatures to reconstruct the final signature.

## Installation

### Prerequisites

- [Python **3.8+**](https://www.python.org/about/gettingstarted/)
- [pip3](https://pip.pypa.io/en/stable/installing/)

### Option 1. Build `bls-horcrux` with native Python

```shell script
pip3 install -r requirements.txt
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
pip install --require-hashes -r requirements.txt
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

### Individual

1. Choose how would you like to execute the commands required to generate your horcrux:

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

2. Choose the option for generating your horcrux:

    - **Offline mode (recommended)** - the horcrux is generated on an air-gapped machine, while the communication with
      other horcruxes is done through the machine connected to the Internet.

    - **Online mode** - the whole process is done on one machine which is connected to the Internet.

## Creating Horcrux

1. Start the BLS horcrux generation process
   (if you want to run in an offline mode, specify `false` in the 3rd question):

    ```shell script
    ./horcrux.sh create
    darwin19
    Running BLS horcrux...
    Enter the total amount of BLS horcruxes: 4
    Enter the minimum number of horcruxes required for recovering the signature: 3
    Enable horcrux creation offline mode (the data to the dispatcher should be submitted separately) [True]:
    Enter the password that secures your horcrux keystore:
    Repeat for confirmation:
    Generating RSA key for communicating with other horcruxes...


    ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC/Zc5kCHui2u2Jj4vt0VX8HDEfDYyOrwKl9PWisZOhvreKtFE5wohfYJsqrV0qemg3uWNc/pt6pIi5XprJn2g/vh18U1if8/kDzQKDb3N1FWN0MAVZZj9qQhDsiwKhtjca4j9GPLNxaAe88f4Ru47qBVc2ptj+BtD64OIH5a1FXlpTlbhHWrLXZTXNLVAykSzs/+ERZfVMYBOK6EBkBbkrI7++Cra9hb/7V5YOfdm6GAU7svAQvuFcKlvH+5D3VV1e0SaqWySq+/3yGdZ5SkUv98z1tFXMNtTH9hu+cbR58ZUVYTK9x5e5uuNit2UJ6wVmWotS9P20ZMEW1h8jJ/r3P4YmucGHCfBsBAolzmwcm2pU2hmDcveRatgfCz7Jdr6yfoIGf3zSHosqNuYuNOEQhFgKm0xDG+XCGQNHXhISFLKDIClA+VcrdZgF4HsSFpNisX1uS0oOwtRz+ldNdN9JpvpzAV/yFLHu3QwX383mN/62xNlbzS42MNkYNqf1Axeied4diNNyFhrchRx4T36UHtqTrJqPyIWmcN6CRruz71kNU8JdMeDHJXSh1t+1bqBoDyAsR2GcR5nBlHx07YKpfLYgxVMBl+DhPlzbLy5aPJijrRk7hezDmbgVKCJTXkVcPg8UJHCIlWupuLmBwqsDXtMRtpUXELF4c369f+tkiw==


    Share the RSA public key above with all other horcruxes
    ```
   **NB!** The `total amount` and `threshold` must be the same for all the participants.

2. Share the RSA public key generated above with every other horcrux holder. You must compose the list of all the RSA
   public keys, save it to the file and submit the path to it.
   **NB!** The list must be equal for all the participants:

    ```shell script
    Enter path to the file with all the RSA public keys [/data/all_rsa_public_keys.txt]:
    Generating intermediate BLS keypair with Shamir's secret sharing: total shares=4, threshold=3
    ```

3. (**Offline mode only**) Save the dispatcher input to the file, move it to your online machine and submit it to the
   dispatcher server:

    - Save dispatcher input to the file on an offline machine:

        ```shell script
        Enter path to the file where the dispatcher input should be saved [/bls-horcrux/data/dispatcher_input.json]:
        Saved dispatcher input to /bls-horcrux/data/dispatcher_input.json. Submit it to the dispatcher server.
        ```

    - Move the `dispatcher_input.json` file to an online machine and submit it to the dispatcher server:

        ```shell script
        ./horcrux.sh handle-dispatcher
        darwin19
        Running BLS horcrux...
        Enter the total amount of BLS horcruxes: 4
        Enter the dispatcher endpoint: https://dispatcher.example.com
        Enter path to the file with the dispatcher input [/bls-horcrux/data/dispatcher_input.json]:
        Successfully submitted dispatcher data
        Waiting for other horcruxes to submit their dispatcher data...
        ```

      **NB!** The `total amount` must be the same as specified in `step 1`.

4. (**Offline mode only**) After all the horcruxes have submitted their dispatcher data, your parts will be fetched and
   saved to the file which should be processed by an offline machine:

    - Save dispatcher output to the file on an online machine:
        ```shell script
        Enter path to the file where the dispatcher output should be saved [/bls-horcrux/data/dispatcher_output.json]:
        Saved dispatcher output data to /bls-horcrux/data/dispatcher_output.json
        Move it to your offline machine to process.
        ```
    - Move dispatcher output to offline machine and specify the path to it:
        ```shell script
        Enter path to the dispatcher output data [/bls-horcrux/data/dispatcher_output.json]:
        ```

5. Specify the path where the horcrux keystore should be stored:
    ```shell script
    Shared BLS Public Key: 0x95dbbf215b9fd18c797f309b95f6eff5756c0e8edf474adfff0358ac25cdcff3aacae8d8e51dc4807a1cd8e99c053c57
    Withdrawal Credentials: 0x007c23c30c3e4bbe983cf5355b6c9e8f1ae1d084e0805e7c889fed91db681e4e
    Enter path to the file where the horcrux should be saved [/bls-horcrux/data/horcrux0.json]:
    Saved horcrux to /bls-horcrux/data/horcrux0.json
    The horcrux file must be stored in a secure place. There will be no way to recover the horcrux if the file will be lost.
    Forgetting your password will also make your horcrux irrecoverable.
    ```

   The generated withdrawal credentials can be used in the ETH2 validator's deposit data and only the threshold of
   horcruxes specified in `step 1` will be able to withdraw its funds.

    **NB! Forgetting the password or losing access to the keystore file will make the horcrux irrecoverable.**

## Signing data

To sign a message, call the command below and pass all the required parameters:

```shell script
./horcrux.sh sign
darwin19
Running BLS horcrux...
Enter the path to the horcrux keystore: /bls-horcrux/data/horcrux0.json
Enter the horcrux password used during your horcrux creation:
Enter hexadecimal encoded data to sign: 0x48656c6c6f20576f726c6421
Signature: 0x88dbee76bca22f82f56bd846f3b2844975191b87dc9cd9fa1823a5fa33607eb188d8dcb4d46e06c69358a7e407c1f3a40c9cece031e8f45259c9731b5e24a32704ef60781a3de1663e2a12a136c9de54e5202f72dc8783afa3180d33258a5528
Horcrux index: 0
```

## Reconstructing threshold signature

To reconstruct a final signature, collect signatures and indexes from other horcruxes (as in section above) and call:

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
 ```
**NB!** Number of signatures should be at least equal to the amount specified in `threshold` from `step 1`
of `Creating Horcrux` section. The data signed must be the same for all the participants.

## Verifying threshold signature

To verify the signature, copy the value of shared BLS public key (`shared_public_key`) from the horcrux keystore and
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
