# Import dependencies
import hvac

def read_secret(vault_url, wrapping_token, path, secret_key, secret_root):
    
    # Instantiate the hvac.Client class
    vault_client = hvac.Client(vault_url, verify=False)

    # Login directly with the wrapped token
    vault_client.auth_cubbyhole(wrapping_token)
    assert vault_client.is_authenticated()

    # Read secret
    read_response = client.secrets.kv.read_secret_version(path=path, mount_point=secret_root)
    secret = read_response['data']['data'][secret_key]

    # Logout and revoke current token
    vault_client.logout(revoke_token=True)

    return secret
