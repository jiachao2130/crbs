// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! crbs-core：CRBS 核心库——engine/state/config 公共实现，供 CLI/server/worker 三端复用。

pub mod auth;
pub mod bind;
pub mod build_options;
pub mod config;
pub mod diff;
pub mod engine;
pub mod error;
pub mod exit_code;
pub mod gc;
pub mod http_retry;
pub mod logging;
pub mod privilege;
pub mod recipe;
pub(crate) mod state;
pub use state::artifacts::{
    Artifact, ArtifactJsonEntry, ArtifactKind, ArtifactsJson, NewArtifact, UploadedArtifactsCommit,
    UploadedArtifactsCommitError,
};
pub use state::audit::{AuditLog, AuditLogFilter};
pub use state::reproducibility::{classify_replay_failure, compare_unsigned_sets, sampling_hit};
pub use state::reproducibility_stats::{
    fold_product_counts, fold_replay_groups, fold_verdict_totals, KindVerdictCount,
    ProductVerdictCount, ReproReplayGroup, ReproReplayRow, ReproSeriesBucket, MAX_STATS_DAYS,
};
pub use state::sessions::SessionRecord;
pub use state::users::{User, UserAuthRow, UserFilter, UserToken};
pub use state::{
    AssignedTaskInfo, Assignment, BatchInsert, BatchItemRecord, BatchProgress, BatchRecord,
    BuildInsert, BuildLifecycle, BuildRecord, CompareDetail, CreateProductInput,
    DeclaredRequirements, DeleteWorkerOutcome, DispatchCandidate, FailedBatchItem, FinalizeOutcome,
    InitConflict, LatestSourceBuild, LearnedGateSnapshot, LearnedWeightSnapshot, NewBatchItem,
    NewReproducibility, NvrGroupFilter, NvrGroupSummary, PackageResourceProfile,
    ProductConfigHistoryEntry, ProductRecord, ProductStub, ProductSummary, ProfileUpdateDecision,
    ReplayVerdict, ReproducibilityRecord, ResolvedProduct, ResourceSampleOutcome, RpmCompareEntry,
    SampleBackend, SkippedBatchItem, StateStore, TaskInsert, TaskRebuildInfo, TaskRecord,
    TelemetrySamplePoint, UpdateOutcome, WorkerActiveBuild, WorkerFilter, WorkerRecentBuild,
    WorkerRecentInit, WorkerStatus, WorkerTelemetry, ALL_VERDICTS, DEFAULT_CENSOR_HEADROOM,
    HUB_LOCAL_WORKER_NAME, KIND_CROSS_ARCH_NOARCH, KIND_REPLAY, RESOURCE_CAP_CGROUP_V2,
    RESOURCE_CAP_IO_STAT, RESOURCE_CAP_MEMORY_EVENTS, RESOURCE_CAP_MEMORY_PEAK, RESOURCE_CAP_PSI,
    SERVER_ROOT_MARKER, TELEMETRY_SAMPLE_QUERY_LIMIT, VISIBILITY_PRIVATE, VISIBILITY_PUBLIC,
};
pub mod sign;
pub mod srpm_token;
pub use types::{
    BuildDurationSample, BuildPriority, ChildBuildSummary, PRIORITY_BACKGROUND, PRIORITY_CRITICAL,
    PRIORITY_DEFAULT,
};
pub mod test_support;
#[cfg(test)]
pub(crate) mod test_util;
pub mod types;
pub mod util;
pub mod validation;

pub use build_options::{
    apply_options_to_engine, build_engine_from_options, effective_build_timeout,
    engine_options_for_reproduce_construction, validate_backend_name, validate_options,
    BuildOptions,
};

pub use engine::backend::ResourceLimits;
pub use error::{is_unique_violation, DbResultExt, Result};
