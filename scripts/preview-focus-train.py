#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["numpy==2.5.3"]
# ///
"""Fit the small whole-plan salience ranker from reviewed workflow labels.

Run with `uv run scripts/preview-focus-train.py --out /tmp/focus-model`.
Only principal-call detail allocation is learned here; facts, permissions,
execution order and the character limit are enforced by the card renderer.
"""

import argparse
import hashlib
import json
import struct
from pathlib import Path

import numpy as np

FEATURES, HIDDEN = 82, 16
SEED = 20260909


def features(classes):
    count = len(classes)
    matrix = np.zeros((count, FEATURES), np.float64)
    for index, category in enumerate(classes):
        matrix[index, category] = 1
        if index > 0:
            matrix[index, 20 + classes[index - 1]] = 1
        if index + 1 < count:
            matrix[index, 40 + classes[index + 1]] = 1
        for context in classes:
            matrix[index, 60 + context] += 1 / count
        matrix[index, 80] = index / max(1, count - 1)
        matrix[index, 81] = int(index == count - 1)
    return matrix


def fit(training):
    rng = np.random.default_rng(SEED)
    weights = rng.normal(0, .12, (FEATURES, HIDDEN))
    bias = np.zeros(HIDDEN)
    output = rng.normal(0, .12, HIDDEN)
    for epoch in range(1800):
        grad_weights = np.zeros_like(weights)
        grad_bias = np.zeros_like(bias)
        grad_output = np.zeros_like(output)
        for matrix, target in training:
            hidden = np.tanh(matrix @ weights + bias)
            logits = hidden @ output
            probabilities = np.exp(logits - logits.max())
            probabilities /= probabilities.sum()
            probabilities[target] -= 1
            grad_output += hidden.T @ probabilities
            grad_hidden = probabilities[:, None] * output[None, :] * (1 - hidden * hidden)
            grad_weights += matrix.T @ grad_hidden
            grad_bias += grad_hidden.sum(0)
        rate = .035 * (.2 + .8 * (1 - epoch / 1800))
        weights -= rate * (grad_weights / len(training) + .001 * weights)
        bias -= rate * grad_bias / len(training)
        output -= rate * (grad_output / len(training) + .001 * output)
    return weights, bias, output


def correct(dataset, model):
    weights, bias, output = model
    return sum(int(np.argmax(np.tanh(matrix @ weights + bias) @ output)) == target
               for matrix, target in dataset)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=Path(__file__).resolve().parents[1]
                        / "crates/ekubo-wallet-preview/model/focus-examples.jsonl")
    parser.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args()
    rows = [json.loads(line) for line in arguments.corpus.read_text().splitlines()]
    patterns = sorted({row["pattern"] for row in rows})
    held = set(patterns[::5])
    training = [(features(row["classes"]), row["focus"]) for row in rows
                if row["pattern"] not in held]
    testing = [(features(row["classes"]), row["focus"]) for row in rows
               if row["pattern"] in held]
    model = fit(training)
    weights, bias, output = model
    blob = b"EKFOCUS1" + struct.pack("<II", FEATURES, HIDDEN)
    blob += np.concatenate([weights.ravel(), bias, output]).astype("<f4").tobytes()
    metrics = {
        "teacher_examples": len(rows), "train": len(training),
        "train_correct": correct(training, model), "held_out": len(testing),
        "held_out_correct": correct(testing, model), "held_out_patterns": sorted(held),
        "seed": SEED, "features": FEATURES, "hidden": HIDDEN, "numpy": np.__version__,
        "teacher": "Qwen2.5-Coder-7B-Instruct Q4_K_M, followed by agent review and correction of principal-outcome labels",
        "teacher_data_sha256": hashlib.sha256(arguments.corpus.read_bytes()).hexdigest(),
        "purpose": "principal-call salience only; never signing authority or factual generation",
        "weights_sha256": hashlib.sha256(blob).hexdigest(),
    }
    arguments.out.mkdir(parents=True, exist_ok=True)
    (arguments.out / "focus.bin").write_bytes(blob)
    (arguments.out / "focus-training.json").write_text(json.dumps(metrics, indent=2) + "\n")
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
