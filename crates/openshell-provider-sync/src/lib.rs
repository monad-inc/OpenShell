// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Keeps `OpenShell` provider credentials in sync with Kubernetes Secrets.
//!
//! Secrets managed outside `OpenShell` (for example by External Secrets
//! Operator) opt in with a label and name the providers and credential keys
//! they back. When a Secret's mapped values change, the controller sends the
//! changed keys to the gateway as a value-only `UpdateProvider`, then
//! restarts the sandboxes attached to that provider so their agents start
//! fresh with the new values. Agents of other providers are not touched.
//!
//! The controller never creates or deletes providers, and never clears a
//! credential when its Secret goes away.

pub mod controller;
pub mod gateway;
pub mod mapping;
pub mod restart;
pub mod state;
pub mod state_store;
