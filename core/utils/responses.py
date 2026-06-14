from flask import jsonify

"""Single place that builds HTTP responses so every endpoint stays
consistent and new endpoints don't have to hand-roll their own shape.

- success_response: arbitrary JSON payload (e.g. an access token or user
  fields) with a 2xx status.
- error_response: the stable ``{"msg": ...}`` error shape used across the
  whole API.
"""


def success_response(payload=None, status=200):
    return jsonify(payload if payload is not None else {}), status


def error_response(msg, status=400):
    return jsonify({"msg": msg}), status
