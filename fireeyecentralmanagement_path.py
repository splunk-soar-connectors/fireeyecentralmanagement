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
from urllib.parse import quote, urlsplit


def build_quarantine_endpoint(prefix, queue_id):
    """Build a confined quarantine endpoint for one opaque queue identifier."""
    if not isinstance(queue_id, str) or not queue_id or queue_id in {".", ".."}:
        raise ValueError("Queue ID must be a non-empty, non-dot string")

    encoded_id = quote(queue_id, safe="")
    expected_path = f"{prefix.rstrip('/')}/{encoded_id}"
    parsed = urlsplit(expected_path)
    if parsed.path != expected_path or parsed.query or parsed.fragment:
        raise ValueError("Queue ID produced an invalid quarantine endpoint")

    return expected_path
