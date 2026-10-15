// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Keeps `OpenShell` provider credentials in sync with Kubernetes Secrets.
//!
//! Secrets managed outside `OpenShell` (for example by External Secrets
//! Operator) opt in with a label and name the providers and credential keys
//! they back. When a Secret's mapped values change, the controller sends the
//! changed keys to the gateway as a value-only `UpdateProvider`. Running
//! sandboxes pick the new values up on their next provider poll, and
//! credentials with `stable_placeholder: true` reach already-running
//! processes too.
//!
//! The controller never creates or deletes providers, and never clears a
//! credential when its Secret goes away.

pub mod controller;
pub mod gateway;
pub mod mapping;
pub mod state;
