# project/tests/test_auth.py


import time
import json
import unittest
import utils

from project.server import db
from project.server.models import User, BlacklistToken
from project.tests.base import BaseTestCase


def register_user(self, email, password):
    return self.client.post(
        '/auth/register',
        data=json.dumps(dict(
            email=email,
            password=password
        )),
        content_type='application/json',
    )

def login_user(self, email, password):
    return self.client.post(
        '/auth/login',
        data=json.dumps(dict(
            email=email,
            password=password
        )),
        content_type='application/json',
    )


class TestAuthBlueprint(BaseTestCase):

    def test_registration(self):
        """ Test for user registration """
        with self.client:
            response = register_user(self, 'joe@gmail.com', '123456')
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'success')
            self.assertTrue(data['message'] == 'Successfully registered.')
            self.assertTrue(data['auth_token'])
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 201)

    def test_registered_with_already_registered_user(self):
        """ Test registration with already registered email"""
        user = User(
            email='joe@gmail.com',
            password='test'
        )
        db.session.add(user)
        db.session.commit()
        with self.client:
            response = register_user(self, 'joe@gmail.com', '123456')
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'fail')
            self.assertTrue(
                data['message'] == 'User already exists. Please Log in.')
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 202)

    def test_registered_user_login(self):
        """ Test for login of registered-user login """
        with self.client:
            # user registration
            resp_register = register_user(self, 'joe@gmail.com', '123456')
            data_register = json.loads(resp_register.data.decode())
            self.assertTrue(data_register['status'] == 'success')
            self.assertTrue(
                data_register['message'] == 'Successfully registered.'
            )
            self.assertTrue(data_register['auth_token'])
            self.assertTrue(resp_register.content_type == 'application/json')
            self.assertEqual(resp_register.status_code, 201)
            # registered user login
            response = login_user(self, 'joe@gmail.com', '123456')
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'success')
            self.assertTrue(data['message'] == 'Successfully logged in.')
            self.assertTrue(data['auth_token'])
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 200)

    def test_non_registered_user_login(self):
        """ Test for login of non-registered user """
        with self.client:
            response = login_user(self, 'joe@gmail.com', '123456')
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'fail')
            self.assertTrue(data['message'] == 'User does not exist.')
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 404)

    def test_user_status(self):
        """ Test for user status """
        with self.client:
            resp_register = register_user(self, 'joe@gmail.com', '123456')
            response = self.client.get(
                '/auth/status',
                headers=utils.login_response_to_authorization_header(resp_register)
            )
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'success')
            self.assertTrue(data['data'] is not None)
            self.assertTrue(data['data']['email'] == 'joe@gmail.com')
            self.assertTrue(data['data']['admin'] is 'true' or 'false')
            self.assertEqual(response.status_code, 200)

    def test_user_add_virtual_identity(self):
        """ Test for adding a virtual identity """
        with self.client:
            user_email = 'joe45@gmail.com'
            user_password = '123456'
            resp_registration = register_user(self, user_email, user_password)
            resp_status = self.client.get(
                '/auth/status',
                headers=utils.login_response_to_authorization_header(resp_registration)
            )
            data = json.loads(resp_status.data.decode())
            user_id = data['data']['user_id']
            resp_add_virtual_user = self.client.post(
                f"/users/{user_id}/analytics",
                headers = utils.login_response_to_authorization_header(resp_registration),
                data=json.dumps(dict(
                    username="test",
                    password="test"
                )),
                content_type='application/json',
            )
            data = json.loads(resp_add_virtual_user.data.decode())
            self.assertTrue(data['status'] == 'success')
            self.assertTrue(data['message'] == 'Successfully added virtual user')
            resp_register = register_user

    def test_user_get_virtual_identity(self):
        """ Test for fetching a virtual identity """
        with self.client:
            user_email = 'joe45@gmail.com'
            user_password = '123456'
            resp_registration = register_user(self, user_email, user_password)
            resp_status = self.client.get(
                '/auth/status',
                headers=utils.login_response_to_authorization_header(resp_registration)
            )
            data = json.loads(resp_status.data.decode())
            user_id = data['data']['user_id']
            virtual_username = "test"
            virtual_password = "test"
            virtual_user_resource = f"/users/{user_id}/analytics"
            resp_add_virtual_user = self.client.post(
                virtual_user_resource,
                headers = utils.login_response_to_authorization_header(resp_registration),
                data=json.dumps(dict(
                    username = virtual_username,
                    password = virtual_password
                )),
                content_type='application/json',
            )
            resp_get_virtual_user = self.client.get(
                virtual_user_resource,
                headers = utils.login_response_to_authorization_header(resp_registration)
            )
            data = json.loads(resp_get_virtual_user.data.decode())
            self.assertTrue(data['status'] == 'success')
            self.assertTrue(data['data']['username'] == virtual_username)
            self.assertTrue(data['data']['password'] == virtual_password)
            resp_register = register_user

    def test_user_add_member_identifier(self):
        """ Test for fetching a core-banking member identifier """
        with self.client:
            user_email = 'joe45@gmail.com'
            user_password = '123456'
            resp_registration = register_user(self, user_email, user_password)
            resp_status = self.client.get(
                '/auth/status',
                headers=utils.login_response_to_authorization_header(resp_registration)
            )
            data = json.loads(resp_status.data.decode())
            user_id = data['data']['user_id']
            member_identifier = "member_" + utils.random_identifier_suffix_4()
            member_resource = f"/users/{user_id}/banking/core"
            resp_add_identifier = self.client.post(
                member_resource,
                headers = utils.login_response_to_authorization_header(resp_registration),
                data=json.dumps(dict(
                    identifier = member_identifier
                )),
                content_type='application/json',
            )
            resp_get_identifier = self.client.get(
                member_resource,
                headers = utils.login_response_to_authorization_header(resp_registration)
            )
            data = json.loads(resp_get_identifier.data.decode())
            self.assertTrue(data['status'] == 'success')
            self.assertTrue(data['data']['identifier'] == member_identifier)
            resp_register = register_user        

    def test_user_no_member_identifier(self):
        """ Test for fetching a core-banking member identifier """
        with self.client:
            user_email = 'joe45@gmail.com'
            user_password = '123456'
            resp_registration = register_user(self, user_email, user_password)
            resp_status = self.client.get(
                '/auth/status',
                headers=utils.login_response_to_authorization_header(resp_registration)
            )
            data = json.loads(resp_status.data.decode())
            user_id = data['data']['user_id']
            member_identifier = "member_" + utils.random_identifier_suffix_4()
            member_resource = f"/users/{user_id}/banking/core"
            resp_get_identifier = self.client.get(
                member_resource,
                headers = utils.login_response_to_authorization_header(resp_registration)
            )
            self.assertEqual(resp_get_identifier.status_code, 404)
            resp_register = register_user        

            
    def test_user_status_malformed_bearer_token(self):
        """ Test for user status with malformed bearer token"""
        with self.client:
            resp_register = register_user(self, 'joe@gmail.com', '123456')
            response = self.client.get(
                '/auth/status',
                headers=dict(
                    Authorization='Bearer' + json.loads(
                        resp_register.data.decode()
                    )['auth_token']
                )
            )
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'fail')
            self.assertTrue(data['message'] == 'Bearer token malformed.')
            self.assertEqual(response.status_code, 401)

    def test_valid_logout(self):
        """ Test for logout before token expires """
        with self.client:
            # user registration
            resp_register = register_user(self, 'joe@gmail.com', '123456')
            data_register = json.loads(resp_register.data.decode())
            self.assertTrue(data_register['status'] == 'success')
            self.assertTrue(
                data_register['message'] == 'Successfully registered.')
            self.assertTrue(data_register['auth_token'])
            self.assertTrue(resp_register.content_type == 'application/json')
            self.assertEqual(resp_register.status_code, 201)
            # user login
            resp_login = login_user(self, 'joe@gmail.com', '123456')
            data_login = json.loads(resp_login.data.decode())
            self.assertTrue(data_login['status'] == 'success')
            self.assertTrue(data_login['message'] == 'Successfully logged in.')
            self.assertTrue(data_login['auth_token'])
            self.assertTrue(resp_login.content_type == 'application/json')
            self.assertEqual(resp_login.status_code, 200)
            # valid token logout
            response = self.client.post(
                '/auth/logout',
                headers=dict(
                    Authorization='Bearer ' + json.loads(
                        resp_login.data.decode()
                    )['auth_token']
                )
            )
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'success')
            self.assertTrue(data['message'] == 'Successfully logged out.')
            self.assertEqual(response.status_code, 200)

    # def test_invalid_logout(self):
    #     """ Testing logout after the token expires """
    #     with self.client:
    #         # user registration
    #         resp_register = register_user(self, 'joe@gmail.com', '123456')
    #         data_register = json.loads(resp_register.data.decode())
    #         self.assertTrue(data_register['status'] == 'success')
    #         self.assertTrue(
    #             data_register['message'] == 'Successfully registered.')
    #         self.assertTrue(data_register['auth_token'])
    #         self.assertTrue(resp_register.content_type == 'application/json')
    #         self.assertEqual(resp_register.status_code, 201)
    #         # user login
    #         resp_login = login_user(self, 'joe@gmail.com', '123456')
    #         data_login = json.loads(resp_login.data.decode())
    #         self.assertTrue(data_login['status'] == 'success')
    #         self.assertTrue(data_login['message'] == 'Successfully logged in.')
    #         self.assertTrue(data_login['auth_token'])
    #         self.assertTrue(resp_login.content_type == 'application/json')
    #         self.assertEqual(resp_login.status_code, 200)
    #         # invalid token logout
    #         time.sleep(6)
    #         response = self.client.post(
    #             '/auth/logout',
    #             headers=dict(
    #                 Authorization='Bearer ' + json.loads(
    #                     resp_login.data.decode()
    #                 )['auth_token']
    #             )
    #         )
    #         data = json.loads(response.data.decode())
    #         self.assertTrue(data['status'] == 'fail')
    #         self.assertTrue(
    #             data['message'] == 'Signature expired. Please log in again.')
    #         self.assertEqual(response.status_code, 401)

    def test_valid_blacklisted_token_logout(self):
        """ Test for logout after a valid token gets blacklisted """
        with self.client:
            # user registration
            resp_register = register_user(self, 'joe@gmail.com', '123456')
            data_register = json.loads(resp_register.data.decode())
            self.assertTrue(data_register['status'] == 'success')
            self.assertTrue(
                data_register['message'] == 'Successfully registered.')
            self.assertTrue(data_register['auth_token'])
            self.assertTrue(resp_register.content_type == 'application/json')
            self.assertEqual(resp_register.status_code, 201)
            # user login
            resp_login = login_user(self, 'joe@gmail.com', '123456')
            data_login = json.loads(resp_login.data.decode())
            self.assertTrue(data_login['status'] == 'success')
            self.assertTrue(data_login['message'] == 'Successfully logged in.')
            self.assertTrue(data_login['auth_token'])
            self.assertTrue(resp_login.content_type == 'application/json')
            self.assertEqual(resp_login.status_code, 200)
            # blacklist a valid token
            blacklist_token = BlacklistToken(
                token=json.loads(resp_login.data.decode())['auth_token'])
            db.session.add(blacklist_token)
            db.session.commit()
            # blacklisted valid token logout
            response = self.client.post(
                '/auth/logout',
                headers=dict(
                    Authorization='Bearer ' + json.loads(
                        resp_login.data.decode()
                    )['auth_token']
                )
            )
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'fail')
            self.assertTrue(data['message'] == 'Token blacklisted. Please log in again.')
            self.assertEqual(response.status_code, 401)

    def test_valid_blacklisted_token_user(self):
        """ Test for user status with a blacklisted valid token """
        with self.client:
            resp_register = register_user(self, 'joe@gmail.com', '123456')
            # blacklist a valid token
            blacklist_token = BlacklistToken(
                token=json.loads(resp_register.data.decode())['auth_token'])
            db.session.add(blacklist_token)
            db.session.commit()
            response = self.client.get(
                '/auth/status',
                headers=dict(
                    Authorization='Bearer ' + json.loads(
                        resp_register.data.decode()
                    )['auth_token']
                )
            )
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'fail')
            self.assertTrue(data['message'] == 'Token blacklisted. Please log in again.')
            self.assertEqual(response.status_code, 401)


if __name__ == '__main__':
    unittest.main()
