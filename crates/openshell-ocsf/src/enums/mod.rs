// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF v1.8.0 enum types.

mod action;
mod activity;
mod auth;
mod device_type;
mod disposition;
mod entity_activity;
mod http_method;
mod launch;
mod managed_entity_type;
mod security;
mod severity;
mod status;
mod user_type;

pub use action::ActionId;
pub use activity::ActivityId;
pub use auth::{AuthActivityId, AuthProtocolId, AuthTypeId};
pub use device_type::DeviceTypeId;
pub use disposition::DispositionId;
pub use entity_activity::EntityActivityId;
pub use http_method::HttpMethod;
pub use launch::LaunchTypeId;
pub use managed_entity_type::ManagedEntityTypeId;
pub use security::{ConfidenceId, RiskLevelId, SecurityLevelId};
pub use severity::SeverityId;
pub use status::{StateId, StatusId};
pub use user_type::UserTypeId;

/// Trait for OCSF enum types that have an integer ID and a string label.
///
/// All OCSF "sibling pair" enums implement this trait, enabling generic
/// serialization of `_id` + label field pairs.
pub trait OcsfEnum: Copy + Clone + PartialEq + Eq + std::fmt::Debug {
    /// Return the integer representation for JSON serialization.
    fn as_u8(self) -> u8;

    /// Return the OCSF string label for this value.
    fn label(self) -> &'static str;
}

/// Implement [`OcsfEnum`] for a type that already has `as_u8()` and `label()` methods.
macro_rules! impl_ocsf_enum {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl OcsfEnum for $ty {
                fn as_u8(self) -> u8 { self.as_u8() }
                fn label(self) -> &'static str { self.label() }
            }
        )+
    };
}

impl_ocsf_enum!(
    ActionId,
    AuthActivityId,
    AuthProtocolId,
    AuthTypeId,
    ConfidenceId,
    DispositionId,
    EntityActivityId,
    LaunchTypeId,
    ManagedEntityTypeId,
    RiskLevelId,
    SecurityLevelId,
    SeverityId,
    StateId,
    StatusId,
    UserTypeId,
);
