//! [`ResourceSpec`] and related types describing compute-resource requirements.

/// Hardware GPU acceleration backend.
#[derive(Copy, Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GpuBackend {
    /// Apple Metal.
    Metal,
    /// NVIDIA CUDA.
    Cuda,
    /// Khronos Vulkan.
    Vulkan,
    /// AMD ROCm.
    Rocm,
    /// Accept any available backend.
    Any,
}

/// Minimum GPU requirements for a task.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct GpuRequirement {
    /// Minimum required video RAM in bytes.
    pub vram_min_bytes: u64,
    /// Required GPU compute backend.
    pub backend: GpuBackend,
}

/// Minimum NPU requirements for a task.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct NpuRequirement {
    /// NPU vendor string (e.g. `"apple"`, `"qualcomm"`).
    pub vendor: String,
}

/// Compute and memory resource requirements for a task.
///
/// All fields are optional minimums; zero/`None` means "no requirement".
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct ResourceSpec {
    /// Number of logical CPU cores required (fractional cores allowed).
    pub cpu_cores: f32,
    /// GPU requirement, if any.
    pub gpu: Option<GpuRequirement>,
    /// NPU requirement, if any.
    pub npu: Option<NpuRequirement>,
    /// Minimum host memory in bytes.
    pub memory_bytes: u64,
    /// Required network bandwidth in bits per second.
    pub network_bandwidth_bps: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_all_zero() {
        let r = ResourceSpec::default();
        assert_eq!(r.cpu_cores, 0.0);
        assert_eq!(r.memory_bytes, 0);
        assert!(r.gpu.is_none());
        assert!(r.npu.is_none());
    }
}
