from teleport_wireguard.teleport import (
    _generate_wg_keys,
    _get_device_name,
    generate_client_hint,
)


def test_generate_client_hint(freeze_uuids):
    assert generate_client_hint() == "00000000-0000-0000-0000-000000000000"


def test_generate_wg_keys(fake_process):
    fake_process.register(["wg", "genkey"], stdout="private_key_abcd")
    fake_process.register(["wg", "pubkey"], stdout="public_key_xyz")
    assert _generate_wg_keys() == ("private_key_abcd", "public_key_xyz")


def test_get_device_name(mocker):
    mocker.patch("socket.gethostname", return_value="fake-hostname")
    assert _get_device_name() == "fake-hostname"
