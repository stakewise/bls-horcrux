from cli.crypto import HorcruxPbkdf2Keystore


def test_it_sets_default_values():
    # when
    result = HorcruxPbkdf2Keystore()

    # then
    result.index == 0
    result.threshold == 0
    result.shared_public_key == ""
    result.shared_withdrawal_credentials == ""


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
    result = HorcruxPbkdf2Keystore.from_json(json_dict=json_dict)

    # then
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
