# File: fireeyecentralmanagement_consts.py
#
# Copyright (c) 2021 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

CM_TOKEN_HEADER = "X-FeApi-Token"
CM_CLIENT_TOKEN_HEADER = "X-FeClient-Token"
CM_BASE_URL = "/wsapis/v2.0.0/"
CM_AUTH_LOGIN_URL = CM_BASE_URL + "auth/login"
CM_AUTH_LOGOUT_URL = CM_BASE_URL + "auth/logout"
CM_ALERTS_URL = CM_BASE_URL + "alerts"
CM_ALERT_URL = CM_BASE_URL + "alerts/alert/"
CM_EMAILMGMT_QUARANTINE = CM_BASE_URL + "emailmgmt/quarantine"

CM_PRODUCTS_MAP = {
    "EX": "EMAIL_MPS",
    "NX": "WEB_MPS",
    "AX": "MAS"
}

CM_PRODUCTS_MAP_REVERSE = {CM_PRODUCTS_MAP[key]: key for key in CM_PRODUCTS_MAP.keys()}


# Constants relating to 'get_error_message_from_exception'
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters."
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters."
ERR_START_AND_END_TIME = "Cannot specify both start time and end time. Please remove either one."
