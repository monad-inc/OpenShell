// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF event formatters: shorthand (human-readable), JSONL, and flat or raw
//! attributes for transports whose unit is a string map (OTLP log records).

pub mod attributes;
pub mod downgrade;
pub mod jsonl;
pub mod shorthand;

pub use jsonl::{event_json, event_json_string};
