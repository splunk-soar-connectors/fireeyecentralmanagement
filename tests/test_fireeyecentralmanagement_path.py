# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from fireeyecentralmanagement_path import build_quarantine_endpoint


PREFIX = "/wsapis/v2.0.0/emailmgmt/quarantine"


def test_build_quarantine_endpoint_rejects_invalid_identifiers():
    for queue_id in (None, 123, "", ".", ".."):
        try:
            build_quarantine_endpoint(PREFIX, queue_id)
        except ValueError as error:
            assert "non-empty, non-dot string" in str(error)
        else:
            raise AssertionError(f"Expected {queue_id!r} to be rejected")


def test_build_quarantine_endpoint_confines_structural_input():
    cases = (
        ("../../auth/user", "..%2F..%2Fauth%2Fuser"),
        ("%2e%2e%2fauth", "%252e%252e%252fauth"),
        ("%252e%252e%252fauth", "%25252e%25252e%25252fauth"),
        ("queue?x=1#fragment", "queue%3Fx%3D1%23fragment"),
    )
    for queue_id, encoded_id in cases:
        assert build_quarantine_endpoint(PREFIX, queue_id) == f"{PREFIX}/{encoded_id}"
