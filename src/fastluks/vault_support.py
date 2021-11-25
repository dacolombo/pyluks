import hvac

def write_secret_to_vault(vault_url, wrapping_token, secret_path, key, value):

    # Instantiate the hvac.Client class
    vault_client = hvac.Client(vault_url, verify=False)

    # Login directly with the wrapped token
    vault_client.auth_cubbyhole(wrapping_token)
    assert vault_client.is_authenticated()

    # Post secret
    secret={key:value}
    vault_client.secrets.kv.v2.create_or_update_secret(path=secret_path, secret=secret, mount_point='secrets', cas=0)

    # Logout and revoke current token
    vault_client.logout(revoke_token=True)
