"""Export a trusted trained artifact and reference outputs for a model-only browser parity experiment."""
import copy
import gzip
import json
from pathlib import Path
import sys

import joblib
import numpy as np
import onnxruntime as ort
import pandas as pd
from onnxmltools import convert_xgboost
from onnxmltools.convert.common.data_types import FloatTensorType

ROOT = Path(__file__).resolve().parents[1]
OUT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import analyzer

model_path = Path(sys.argv[1])
model = joblib.load(model_path)
frame = pd.read_csv(ROOT / 'data/test.csv')
urls = frame.url.tolist()
normalized = [analyzer.normalize_for_analysis(url) for url in urls]
X = pd.DataFrame([analyzer.extract_features(url) for url in normalized])[analyzer.FEATURE_COLS].astype(np.float32)
expected = model.predict_proba(X)
classes = ['benign', 'malware', 'phishing']
# onnxmltools requires positional f0.. names; changing the copied metadata does not alter trees.
export_model = copy.deepcopy(model)
export_model.get_booster().feature_names = [f'f{i}' for i in range(len(analyzer.FEATURE_COLS))]
onnx = convert_xgboost(export_model, initial_types=[('input', FloatTensorType([None, len(analyzer.FEATURE_COLS)]))], target_opset=15)
(OUT / 'model.onnx').write_bytes(onnx.SerializeToString())
session = ort.InferenceSession(str(OUT / 'model.onnx'), providers=['CPUExecutionProvider'])
converted = session.run(None, {'input': X.to_numpy()})[1]
max_error = float(np.abs(expected - converted).max())
label_changes = int(np.count_nonzero(expected.argmax(1) != converted.argmax(1)))
assert max_error < 1e-5, max_error
assert label_changes == 0, label_changes
payload = {'urls': urls, 'features': X.values.tolist(), 'probabilities': expected.tolist(), 'labels': expected.argmax(1).tolist(), 'truth': frame.label.tolist()}
(OUT / 'reference.json').write_text(json.dumps(payload, separators=(',', ':')))
feature_config = {
    'brands': list(analyzer.BRANDS), 'suspiciousKeywords': list(analyzer.SUSPICIOUS_KEYWORDS),
    'shorteners': list(analyzer.SHORTENERS), 'safeTlds': list(analyzer.SAFE_TLDS),
    'suspiciousTlds': list(analyzer.SUSPICIOUS_TLDS), 'safeCountryTlds': list(analyzer.SAFE_COUNTRY_TLDS),
    'safeExtensions': list(analyzer.SAFE_EXTENSIONS),
}
sizes = {}
for name in ['model.onnx', 'reference.json']:
    data = (OUT / name).read_bytes()
    sizes[name] = {'bytes': len(data), 'gzipBytes': len(gzip.compress(data, mtime=0))}
metadata = {
    'features': analyzer.FEATURE_COLS, 'classes': classes, 'featureConfig': feature_config,
    'modelBytes': sizes['model.onnx']['bytes'], 'sizes': sizes,
    'pickleBytes': model_path.stat().st_size, 'testRows': len(frame),
    'modelOnlyAccuracy': float(np.mean(np.array(classes)[expected.argmax(1)] == frame.label.to_numpy())),
    'pythonOnnxMaxProbabilityError': max_error, 'pythonOnnxLabelChanges': label_changes,
    'treeCount': len(model.get_booster().get_dump()), 'bestIteration': model.best_iteration,
    'scope': 'Model scoring only; this is not the full DeepIntel detection pipeline.',
}
metadata['runtimeSizes'] = {}
for name in ['ort.wasm.min.js', 'ort-wasm-simd-threaded.wasm', 'ort-wasm-simd-threaded.mjs']:
    runtime = OUT / 'node_modules/onnxruntime-web/dist' / name
    if runtime.exists():
        data = runtime.read_bytes()
        metadata['runtimeSizes'][name] = {'bytes': len(data), 'gzipBytes': len(gzip.compress(data, mtime=0))}
(OUT / 'metadata.json').write_text(json.dumps(metadata, indent=2))
print(json.dumps({key: value for key, value in metadata.items() if key not in ['featureConfig','features']}, indent=2))
