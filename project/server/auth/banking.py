
from flask import Blueprint, request, make_response, jsonify, abort
from flask.views import MethodView

from project.server import bcrypt, db
from project.server.models import User, BlacklistToken, VirtualUser
from project.server.auth.constants import Constants

class BankingCoreUsersAPI(MethodView):
    """
    User Resource
    """
    def get(self, user_id):
        # get the auth token
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                auth_token = auth_header.split(" ")[1]
            except IndexError:
                responseObject = {
                    'status': 'fail',
                    'message': 'Bearer token malformed.'
                }
                return make_response(jsonify(responseObject)), 401
        else:
            auth_token = ''
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            if not isinstance(resp, str):
                authenticated_user = User.query.filter_by(id=resp).first()
                responseObject = self.successful_response_object(authenticated_user, user_id)
                return make_response(jsonify(responseObject)), 200
            responseObject = {
                'status': 'fail',
                'message': resp
            }
            return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 401

    def post(self, user_id):
        # get the post data
        post_data = request.get_json()
        # check if user already exists
        user = User.query.filter_by(id=user_id).first()
        identifier = post_data.get('identifier')
        # if not user:
        if not False:
            try:
                user.core_banking_identifier = identifier
                db.session.commit()
                # generate the auth token
                auth_token = user.encode_auth_token(user.id)
                responseObject = {
                    'status': 'success',
                    'message': 'Successfully added identifier',
                }
                return make_response(jsonify(responseObject)), 201
            except Exception as e:
                responseObject = {
                    'status': 'fail',
                    'message': 'Some error occurred. Please try again.',
                }
                return make_response(jsonify(responseObject)), 401
        
    def successful_response_object(self, authenticated_user, requested_user_id):
        if requested_user_id:
            requested_user = User.query.filter_by(id=requested_user_id).first()
            if not requested_user:
                abort(404)
            if not requested_user.core_banking_identifier:
                abort(404)
            else:
                responseObject = {
                    'status': 'success',
                    'data': {
                        'identifier': requested_user.core_banking_identifier,
                        'username': Constants.operator_username,
                        'password': Constants.operator_password,
                    }
                }
        return responseObject
