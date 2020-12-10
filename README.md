# BLS Horcrux

## Introduction

`bls-horcrux` is a tool for creating a threshold BLS key in a trustless manner. It uses [Shamir's secret sharing](https://launchpad.ethereum.org/faq#keys)
and [BLS properties](https://blog.dash.org/secret-sharing-and-threshold-signatures-with-bls-954d1587b5f) to create a key
 which is shared by `m` parties and requires `n out of m` signatures to reconstruct the final signature.

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
pip install -r requirements.txt
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
- **Dispatcher** - what endpoint should be used for the horcruxes to communicate ([See dispatcher](./dispatcher/README.md)).

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

    - **Offline mode (recommended)** - the horcrux is generated on an air-gapped machine, while the communication
      with other horcruxes is done through the machine connected to the Internet.

    - **Online mode** - the whole process is done on one machine which is connected to the Internet.

## Usage

1. Start the BLS horcrux generation process
   (if you want to run in an offline mode, specify `false` in the 3rd question):

    ```shell script
    ./horcrux.sh create
    darwin19
    Running BLS horcrux...
    Enter the total amount of BLS horcruxes: 3
    Enter the minimum number of horcruxes required for recovering the signature: 2
    Enable horcrux creation offline mode (the data to the dispatcher should be submitted separately) [True]:
    Enter the path to the file where the private key will be saved [/data/keystore.json]:
    Enter the password that secures your horcrux keystore:
    Repeat for confirmation:
    Generating RSA key for communication with other horcruxes...
    Saved RSA public key to /data/my_rsa_public_key.txt. Please share it with other horcruxes.
    Waiting for all the horcruxes RSA public keys at /data/all_rsa_public_keys.txt.
    The keys order inside the file must be the same for all the horcruxes.
    ```

    NB! The `total amount` and `threshold` must be the same for all the participants.

2. Share the public RSA key located in `/data/my_rsa_public_key.txt` with every other horcrux holder.
    You must compose the list of all the public key holders and place it to `/data/all_rsa_public_keys.txt`.
    **NB!** The list must be equal for all the participants.

    After creating `/data/all_rsa_public_keys.txt`, you should see the following log message:

    ```shell script
    Generating BLS keypair with Shamir's secret sharing: total shares=3, threshold=2
    Saved dispatcher input to /data/dispatcher_input.json. Please submit it to the dispatcher server.
    Waiting for dispatcher output file to be created at /data/dispatcher_output.json...
    ```

3. (**Offline mode only**) Copy the `/data/dispatcher_input.json` to your online machine's `/data/` directory and submit it to
   the dispatcher server with the command:

    ```shell script
    ./horcrux.sh handle-dispatcher
    darwin19
    Running BLS horcrux...
    Enter the total amount of BLS horcruxes: 3
    Enter the dispatcher endpoint: https://dispatcher.example.com
    Successfully submitted dispatcher data
    ```

4. (**Offline mode only**) Copy the `/data/dispatcher_output.json` from your online machine's `/data/` directory to your offline
   machine's `/data/` directory. It will be automatically processed:

    ```shell script
    Shared BLS Public Key:
    0x8ec7a87ea7d41d790f9cc349589983ac3c72d2c292bd702180a493bb334388c158988b0b8dac182390ca90a64c75c9c6
    Saved horcrux BLS private key to /data/keystore.json
    ```

5. To sign a message, place it to the `/data/signing_data.txt` file in a hexadecimal format and call:

    ```shell script
    ./horcrux.sh sign
    darwin19
    Running BLS horcrux...
    Enter the path to the file where the private key will be saved [/data/keystore.json]:
    Enter the path to the file where signing data is stored in hexadecimal format [/data/signing_data.txt]:
    Enter the keystore password used during your horcrux encryption:
    Signature:
    0x80c324a4eb2987c7969f6a9604200c0c364dc2f8de9cf6cc0b4697161ab7611c0996bdcf4faac241a361322eecc041541715908c5e62bfcd02220d29529692d66e547e58c7031c47cc5074a622fc47c23054eb93c4349f5dc4505123ce1d4b04
    Horcrux index: 2
    ```

6. To reconstruct a final signature, collect signatures and indexes from other horcruxes and call:

    ```shell script
    ./horcrux.sh reconstruct-signature
    darwin19
    Running BLS horcrux...
    Enter the total number of BLS signatures to reconstruct the final signature from: 2
    Enter the next hexadecimal encoded BLS signature (1/2): 0x80c324a4eb2987c7969f6a9604200c0c364dc2f8de9cf6cc0b4697161ab7611c0996bdcf4faac241a361322eecc041541715908c5e62bfcd02220d29529692d66e547e58c7031c47cc5074a622fc47c23054eb93c4349f5dc4505123ce1d4b04
    Enter the horcrux index of the submitted signature (can be found in keystore file): 2
    Enter the next hexadecimal encoded BLS signature (2/2): 0x8bccdf5f9b2ec8e681b6f3e12ca646b76e3422196e146634792f6dcf170cf52f17fe8e806b9d5272491423462777ddb011e776ee79d9cf73a59908a6fea9ea93837ffe0e6268850f6b50a5407f891fa590e848cc2c7bd2a8480c8160cdfdc17f
    Enter the horcrux index of the submitted signature (can be found in keystore file): 1
    Reconstructed signature:
    0x83ee4d5c28b00c28a4ceb25e2bb8b2391f659368b4936386321007ff148c25541f807ab8f16785fb1cb26b10220daf8202c95ed66e747cc31a003087f1ccea79434d90e9ca163c5d7f7d1102992b81e96c2b6b69f9b716940a18a7c6e8dbef25
    ```
   **NB!** Number of signatures should be at least equal to the amount specified in `threshold` in `keystore.json`.
   The data signed must be the same for all the participants.

7. To verify the signature, copy the public key from the `/data/keystore.json`,
   place hexadecimal encoded message to `/data/signing_data.txt` and call:

    ```shell script
    ./horcrux.sh verify-signature
    darwin19
    Running BLS horcrux...
    Enter the hexadecimal encoded BLS public key to verify: 0x8ec7a87ea7d41d790f9cc349589983ac3c72d2c292bd702180a493bb334388c158988b0b8dac182390ca90a64c75c9c6
    Enter the hexadecimal encoded BLS signature to verify: 0x83ee4d5c28b00c28a4ceb25e2bb8b2391f659368b4936386321007ff148c25541f807ab8f16785fb1cb26b10220daf8202c95ed66e747cc31a003087f1ccea79434d90e9ca163c5d7f7d1102992b81e96c2b6b69f9b716940a18a7c6e8dbef25
    Enter the path to the file where signing data is stored in hexadecimal format [/app/data/signing_data.txt]:
    [+] The signature is valid
    ```
