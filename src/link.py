import base64
import datetime
import hashlib
import hmac


PERMITTED_HASH_METHODS = ('sha256', 'sha384', 'sha512')


def create_link_code(data: str, valid_for_seconds: int, key: bytes, hash_method: str = 'sha256') -> str:

    # get valid until datetime
    valid_until = (
            datetime.datetime.now(tz=datetime.timezone.utc) +
            datetime.timedelta(seconds=valid_for_seconds)
    ).isoformat()

    # make sure the hash method is valid
    if hash_method.lower() not in hashlib.algorithms_available:
        raise ValueError(f'Invalid hash algo: {hash_method}')

    # make sure the hash method is permitted
    if hash_method.lower() not in PERMITTED_HASH_METHODS:
        raise ValueError(f'Invalid hash algo: {hash_method}')

    # create the message
    message = f"{hash_method.lower()}|{valid_until}|{data}".encode()

    # create the message digest
    digest = hmac.new(key, message, hash_method).digest()

    # create the link_bytes
    link_bytes = message + digest

    # base64 encode the link_bytes
    link_code = base64.urlsafe_b64encode(link_bytes)
    return link_code.decode()


def validate_link_code(link_code: str, key: bytes) -> tuple[str, datetime.datetime, str]:
    """
    :param link_code:
    :param key: the key to use for message digest validation
    :return: tuple (data, valid_until_date, hash_method)
    """
    # base64 decode
    link_bytes = base64.urlsafe_b64decode(link_code)

    # get the hash method
    hash_method, *_ = link_bytes.split(b'|', 1)
    hash_method = hash_method.decode().lower()  # convert to str
    if hash_method not in hashlib.algorithms_available:
        raise ValueError('Unsupported hash method')
    hash_obj = hashlib.new(hash_method)

    # split message and digest
    digest = link_bytes[-hash_obj.digest_size:]  # get digest
    message = link_bytes[:-hash_obj.digest_size]

    # validate digest
    expected_digest = hmac.new(key, message, hash_method).digest()
    if not hmac.compare_digest(expected_digest, digest):
        raise ValueError('Invalid message digest')

    # unpack the message
    hash_method, valid_until_isodate, data = message.decode().split('|')
    valid_until_date = datetime.datetime.fromisoformat(valid_until_isodate)

    # check message still valid
    if valid_until_date < datetime.datetime.now(tz=datetime.timezone.utc):
        raise ValueError('Link code expired')
    return data, valid_until_date, hash_method
