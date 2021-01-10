from cli.crypto import (
    HorcruxPbkdf2Keystore,
    DEFAULT_SHARED_WITHDRAWAL_CREDS,
    DEFAULT_SHARED_PUBLIC_KEY,
    DEFAULT_INDEX,
    DEFAULT_THRESHOLD,
)


def test_it_sets_default_values():
    # when
    result = HorcruxPbkdf2Keystore()

    # then
    assert result.index == DEFAULT_INDEX
    assert result.threshold == DEFAULT_THRESHOLD
    assert result.shared_public_key == DEFAULT_SHARED_PUBLIC_KEY
    assert result.shared_withdrawal_credentials == DEFAULT_SHARED_WITHDRAWAL_CREDS
    assert result.crypto is not None
    assert result.description is not None
    assert result.pubkey is not None
    assert result.path is not None
    assert result.uuid is not None
    assert result.version is not None


def test_it_creates_keystore_from_json():
    # given
    json_dict = {
        "index": 1,
        "threshold": 11,
        "shared_public_key": "any_shared_public_key",
        "shared_withdrawal_credentials": "any_withdrawal_creds",
        "crypto": {
            "kdf": {"function": "any_kdf_func"},
            "checksum": {"function": "any_kdf_func"},
            "cipher": {"function": "any_kdf_func"},
        },
        "path": "any_path",
        "uuid": "any_uuid_str",
        "version": 111,
    }

    # when
    result = HorcruxPbkdf2Keystore.create_from_json(json_dict=json_dict)

    # then
    assert isinstance(result, HorcruxPbkdf2Keystore)
    assert result.index == json_dict["index"]
    assert result.threshold == json_dict["threshold"]
    assert result.shared_public_key == json_dict["shared_public_key"]
    assert (
        result.shared_withdrawal_credentials
        == json_dict["shared_withdrawal_credentials"]
    )
    assert result.path == json_dict["path"]
    assert result.uuid == json_dict["uuid"]
    assert result.version == json_dict["version"]
    assert result.crypto.kdf.function == json_dict["crypto"]["kdf"]["function"]
    assert (
        result.crypto.checksum.function == json_dict["crypto"]["checksum"]["function"]
    )
    assert result.crypto.cipher.function == json_dict["crypto"]["cipher"]["function"]


def test_it_creates_keystore_from_private_key():
    # given
    private_key = 999
    password = "any_password"
    index = 1
    threshold = 11
    shared_public_key = "any_shared_public_key"
    shared_withdrawal_credentials = "any_withdrawal_creds"

    # when
    result = HorcruxPbkdf2Keystore.create_from_private_key(
        private_key=private_key,
        password=password,
        index=index,
        threshold=threshold,
        shared_public_key=shared_public_key,
        shared_withdrawal_credentials=shared_withdrawal_credentials,
    )

    # then
    assert isinstance(result, HorcruxPbkdf2Keystore)
    assert result.pubkey == (
        "b94ba65546846b439edbfc9da84c1c2d2af3d0ede8c88ec50fce2e1c"
        "3f782e932205982683f0802a4dce313610bbb2db"
    )
    assert result.index == index
    assert result.threshold == threshold
    assert result.shared_public_key == shared_public_key
    assert result.shared_withdrawal_credentials == shared_withdrawal_credentials
