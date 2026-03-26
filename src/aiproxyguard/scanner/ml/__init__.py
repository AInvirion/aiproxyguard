# Copyright 2025-2026 AInvirion LLC
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

"""ML-based classifier for semantic prompt filtering."""

from aiproxyguard.scanner.ml.classifier import MLClassifier, MLMatch
from aiproxyguard.scanner.ml.license import (
    License,
    decrypt_model,
    is_license_valid,
    load_licensed_model,
    parse_license,
    verify_license_signature,
)
from aiproxyguard.scanner.ml.metrics import (
    MLClassifierMetrics,
    get_ml_metrics,
    reset_ml_metrics,
)

__all__ = [
    # Classifier
    "MLClassifier",
    "MLMatch",
    # License
    "License",
    "decrypt_model",
    "is_license_valid",
    "load_licensed_model",
    "parse_license",
    "verify_license_signature",
    # Metrics
    "MLClassifierMetrics",
    "get_ml_metrics",
    "reset_ml_metrics",
]
