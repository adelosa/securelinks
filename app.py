from flask import Flask, request
from src.link import create_link_code, validate_link_code

app = Flask(__name__)

KEY = b'1234567812345678'
HASH_METHOD = 'sha512'


@app.route('/')
def root():
    return 'EmailUpdater'


@app.route('/link', methods=['GET'])
def link():
    """
    Generate a time bound link code

    :return: the link code
    """
    if not (data := request.args.get('data')):
        return 'Invalid request', 400

    link_code = create_link_code(data, 300, KEY, HASH_METHOD)
    return link_code, 200


@app.route('/link/<string:link_code>', methods=['GET'])
def link_validate_url(link_code: str):

    data, valid_until, _ = validate_link_code(link_code, KEY)

    return f"{data}, {valid_until}", 200


@app.route('/validate', methods=['GET'])
def link_validate():
    """
    Validate a link code

    :return: 200: OK
    """
    if not (link_code := request.args.get('link_code')):
        return 'Invalid request', 400
    print(link_code)

    email, valid_until, _ = validate_link_code(link_code, KEY)

    return f"{email}, {valid_until}", 200


if __name__ == '__main__':
    app.run(debug=True, port=5000)
