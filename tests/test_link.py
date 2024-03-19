import datetime
import unittest

from src import link


class TestLink(unittest.TestCase):

    def test_link_create_validate(self):
        key = b'12345678'
        link_code = link.create_link_code('email=adelosa@gmail.com', 20, key)
        print(link_code)
        data, valid_until, hash_method = link.validate_link_code(link_code, key)
        self.assertEqual('email=adelosa@gmail.com', data)
        self.assertEqual('sha256', hash_method)

    def test_link_create_validate_diff_hash_method(self):
        key = b'12345678'
        start_time = datetime.datetime.now(tz=datetime.timezone.utc)
        link_code = link.create_link_code('email=adelosa@gmail.com', 20, key, hash_method='sha512')
        data, valid_until, hash_method = link.validate_link_code(link_code, key)
        end_time = datetime.datetime.now(tz=datetime.timezone.utc)
        self.assertEqual('email=adelosa@gmail.com', data)
        self.assertEqual('sha512', hash_method)
        self.assertGreater(valid_until, start_time)
        self.assertLess(valid_until, end_time + datetime.timedelta(seconds=20))

    def test_link_create_validate_invalid_hash_method(self):
        key = b'12345678'
        with self.assertRaises(ValueError) as context:
            link.create_link_code('email=adelosa@gmail.com', 20, key, hash_method='md5')
        self.assertEqual('Invalid hash algo: md5', context.exception.args[0])

    def test_link_validate_fail_past_valid_datetime(self):
        key = b'12345678'
        # setting valid for seconds means will never be valid
        link_code = link.create_link_code('email=adelosa@gmail.com', 0, key)
        with self.assertRaises(ValueError) as context:
            link.validate_link_code(link_code, key)
        self.assertEqual('Link code expired', context.exception.args[0])

    def test_link_validate_fail_bad_digest(self):
        key = b'12345678'
        # setting valid for seconds means will never be valid
        link_code = link.create_link_code('email=adelosa@gmail.com', 0, key)
        # force bad digest by using a different key
        with self.assertRaises(ValueError) as context:
            link.validate_link_code(link_code, b'87654321')
        self.assertEqual('Invalid message digest', context.exception.args[0])


if __name__ == '__main__':
    unittest.main()
